from fastapi import HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict
import json
# We no longer need the whole workflow, just the node functions and their tools
from langgraph_cve_tools import trivy_scanner, json_to_csv_converter, cve_classifier, cve_report_generator
from cve_analyzer_langgraph_final import analyze_single_cve, expert_team_graph
from concurrent.futures import ThreadPoolExecutor
import logging
# --- Define API Models ---
class ScanRequest(BaseModel):
    target_image: str
    base_image: str

class ScanResponse(BaseModel):
    target_scan_path: str
    base_scan_path: str

class ClassifyRequest(BaseModel):
    target_scan_path: str
    base_scan_path: str

class ClassifyResponse(BaseModel):
    type1_cves: List[Dict]
    type2_cves: List[Dict]
    type3_cves: List[Dict]

class ExpertAnalysisRequest(BaseModel):
    type1_cves: List[Dict]
    type2_cves: List[Dict]
    type3_cves: List[Dict] = Field(description="List of Type-3 CVEs to be analyzed by experts.")

class ExpertAnalysisResponse(BaseModel):
    type1_cves: List[Dict]
    type2_cves: List[Dict]
    expert_analysis_results: List[Dict]

class ReportRequest(BaseModel):
    type1_cves: List[Dict]
    type2_cves: List[Dict]
    expert_analysis_results: List[Dict]

class ReportResponse(BaseModel):
    final_report_message: str





from mcp.server.fastmcp import FastMCP



mcp = FastMCP("CVE Task",port=20048)



@mcp.tool()
async def scan_images(request: ScanRequest) -> ScanResponse:
    """Step 1: Scans the target and base Docker images."""
    try:
        # This logic is taken directly from your scan_images_node
        with ThreadPoolExecutor() as executor:
            future_target = executor.submit(trivy_scanner.invoke, {"image_name": request.target_image})
            future_base = executor.submit(trivy_scanner.invoke, {"image_name": request.base_image})
            target_res, base_res = json.loads(future_target.result()), json.loads(future_base.result())

        if "error" in target_res or "error" in base_res:
            raise HTTPException(status_code=400, detail=f"Image scanning failed. Target: {target_res.get('error')}, Base: {base_res.get('error')}")
        
        return {"target_scan_path": target_res["output_path"], "base_scan_path": base_res["output_path"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@mcp.tool()
async def classify_cves(request: ClassifyRequest) -> ClassifyResponse:
    """Step 2: Converts scan results to CSV and classifies CVEs."""
    try:
        # This logic is taken directly from your classify_cves_node
        target_csv_res = json.loads(json_to_csv_converter.invoke({"json_file_path": request.target_scan_path}))
        base_csv_res = json.loads(json_to_csv_converter.invoke({"json_file_path": request.base_scan_path}))
        logging.info(target_csv_res["output_path"])
        logging.info(base_csv_res["output_path"])
        classification_result = cve_classifier.invoke({"target_csv_path": target_csv_res["output_path"], "base_csv_path": base_csv_res["output_path"]})
        logging.info("classification done")

        return {
            "type1_cves": classification_result["type1_cves"],
            "type2_cves": classification_result["type2_cves"],
            "type3_cves": classification_result["type3_cves_to_analyze"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@mcp.tool()
async def expert_analysis(request: ExpertAnalysisRequest) -> ExpertAnalysisResponse:
    try:
        # 并行处理Type-3 CVEs
        analysis_results = []
        logging.info("init analysis results list")
        if request.type3_cves:
            with ThreadPoolExecutor(max_workers=5) as executor:
                analysis_results = list(executor.map(analyze_single_cve, request.type3_cves))
        
        # 保持原始Type-1/2数据不变，仅添加分析结果
        return {
            "type1_cves": request.type1_cves,
            "type2_cves": request.type2_cves,
            "expert_analysis_results": analysis_results
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )
    
@mcp.tool()
async def generate_report(request: ReportRequest):
    """Step 4: Generates the final report from all classified CVE data."""
    try:
        # This logic is taken directly from your final_report_node
        final_payload = {"classified_cves": {
            "type1_cves": request.type1_cves,
            "type2_cves": request.type2_cves,
            "type3_results": request.expert_analysis_results
        }}
        report_message = cve_report_generator.invoke(final_payload)
        return {"final_report_message": report_message}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
if __name__ == "__main__":
    mcp.run(transport="sse")