# cve_analyzer_langgraph_final.py
import json
import logging
from typing import List, TypedDict
from concurrent.futures import ThreadPoolExecutor

from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
from langchain_community.tools import ShellTool
from langchain_openai import ChatOpenAI 
from langgraph.graph import StateGraph, END
from pydantic import BaseModel
from langgraph_cve_tools import (
    trivy_scanner, 
    json_to_csv_converter, 
    cve_classifier, 
    cve_report_generator
)

def create_shell_tools_from_config(mcp_config: dict) -> List[ShellTool]:
    """Dynamically creates ShellTools from the mcpServers configuration."""
    tools = []
    for name, config in mcp_config.items():
        command_str = f"{config['command']} {' '.join(config.get('args', []))}"
        tool_instance = ShellTool(name=name, description=f"Executes: '{command_str}'.", command=command_str)
        tools.append(tool_instance)
    logging.info(f"Created {len(tools)} shell tools from config.")
    return tools


# --- Global Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Part 1: LLM and Agent Configuration ---
llm = ChatOpenAI(
    model="Qwen/Qwen3-Coder-480B-A35B-Instruct",
    max_tokens=4096, # Set a reasonable max_tokens
    timeout=120,    # Set a timeout in seconds
    max_retries=2,
    api_key="ms-30184ba8-077f-4abf-a40d-97e8d6fc7cb7", 
    base_url="https://api-inference.modelscope.cn/v1",
)

mcpServers_config = {
    'time': { 'command': 'date' },
    'fetch': { 'command': 'curl', 'args': ['-L'] },
    'filesystem_ls': { 'command': 'ls', 'args': ['-l', '.'] } 
}
mcp_tools = create_shell_tools_from_config(mcpServers_config)


analyst_system_prompt = """
You are the 'CVE Analyst'. Your task is to analyze the given CVE vulnerability based on the provided data.
You MUST reply ONLY with a valid JSON object in the following format, with no additional text or markdown:
{
    "risk_level": "High/Medium/Low",
    "whether_relevant": "Yes/No",
    "analysis": "Detailed impact analysis explaining why it is or is not relevant.",
    "suggestion": "Concrete fix suggestions if relevant, otherwise state 'N/A'.",
    "workaround": "A temporary workaround if any, otherwise leave empty."
}
"""
analyst_llm = llm.bind_tools(mcp_tools)


auditor_system_prompt = """
You are the 'CVE Auditor'. You will review the analysis from the 'CVE Analyst'.
Your task is to assess if the analysis is comprehensive, logical, and credible.
You MUST reply ONLY with a valid JSON object in the following format, with no additional text or markdown:
{
    "is_credible": true/false,
    "critique": "If not credible, provide specific feedback and what needs to be investigated further. If credible, this can be a short confirmation like 'Analysis is sound.'"
}
"""

class AuditorOutput(BaseModel):
    is_credible: bool
    critique: str

auditor_llm = llm.with_structured_output(AuditorOutput)

class MessagesState(TypedDict):
    messages: List[BaseMessage]

def analyst_node(state: MessagesState):
    response = analyst_llm.invoke(analyst_system_prompt + "\n\n" + "\n".join([m.content for m in state['messages']]))
    return {"messages": [response]}

generator_graph = StateGraph(MessagesState).add_node("generate", analyst_node).set_entry_point("generate").add_edge("generate", END).compile()

def auditor_node(state: MessagesState):
    analysis_message = state['messages'][-1]
    prompt_for_auditor = f"Please audit the following CVE analysis and respond in JSON format:\n\n{analysis_message.content}"
    critique_obj: AuditorOutput = auditor_llm.invoke(auditor_system_prompt + "\n\n" + prompt_for_auditor)
    
    if not critique_obj.is_credible:
        logging.warning(f"Analysis failed audit. Critique: {critique_obj.critique}")
        return {"messages": [HumanMessage(content=critique_obj.critique)]}
    else:
        logging.info("Analysis passed audit.")
        return {"messages": [AIMessage(content="Audit passed.")]}

reflector_graph = StateGraph(MessagesState).add_node("reflect", auditor_node).set_entry_point("reflect").add_edge("reflect", END).compile()

class ReflectionState(TypedDict):
    messages: List[BaseMessage]
    reflection_count: int

def should_reflect(state: ReflectionState):
    if state["reflection_count"] >= 3:
        logging.warning("Reflection limit reached, exiting loop.")
        return END
    last_msg = state["messages"][-1]
    if isinstance(last_msg, AIMessage) and last_msg.content == "Audit passed":
        return END
    return "analyze_and_reflect"

def expert_team_node(state: ReflectionState):
    analysis_result = generator_graph.invoke({"messages": state["messages"]})
    reflection_result = reflector_graph.invoke({"messages": analysis_result["messages"]})
    all_messages = state["messages"] + analysis_result["messages"] + reflection_result["messages"]
    return {"messages": all_messages, "reflection_count": state.get("reflection_count", 0) + 1}

expert_team_graph = StateGraph(ReflectionState).add_node("analyze_and_reflect", expert_team_node).set_entry_point("analyze_and_reflect").add_conditional_edges("analyze_and_reflect", should_reflect).compile()

def analyze_single_cve(cve: dict) -> dict:
    cve_id = cve.get('VulnerabilityID')
    logging.info(f"analysis for {cve_id} begin \n")
    initial_prompt = f"Please analyze the following CVE:\n\n{json.dumps(cve, indent=2, ensure_ascii=False)}"
    logging.info(f"initial prompt show below: \n {initial_prompt} \n")
    initial_state = {"messages": [HumanMessage(content=initial_prompt)], "reflection_count": 0}
    logging.info(f"initial state show below: \n {initial_state} \n")
    final_state = expert_team_graph.invoke(initial_state)
    
    final_analysis_msg = None
    for i in range(len(final_state["messages"]) - 1, 0, -1):
        if final_state["messages"][i].content == "Audit passed":
            final_analysis_msg = final_state["messages"][i-1]
            break
    if not final_analysis_msg and len(final_state["messages"]) > 1:
        if isinstance(final_state["messages"][-1], AIMessage):
             final_analysis_msg = final_state["messages"][-1] # reflection limit reached case
        elif len(final_state["messages"]) > 2:
             final_analysis_msg = final_state["messages"][-2]

    if final_analysis_msg and isinstance(final_analysis_msg, AIMessage):
        try:
            return {"cve": cve, "analysis": json.loads(final_analysis_msg.content)}
        except json.JSONDecodeError:
            return {"cve": cve, "analysis": {"error": "Invalid JSON output from analyst."}}
    return {"cve": cve, "analysis": {"error": "Analysis failed to produce valid output."}}
