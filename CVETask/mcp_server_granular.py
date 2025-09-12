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



mcp = FastMCP("test", host="arda-multiarc-001.sh.intel.com", port=10001)



# @mcp.tool()
# async def scan_images(target_image:str, base_image:str):
#     """Step 1: Scans the target and base Docker images."""
#     try:
#         # This logic is taken directly from your scan_images_node
#         with ThreadPoolExecutor() as executor:
#             future_target = executor.submit(trivy_scanner.invoke, {"image_name": target_image})
#             future_base = executor.submit(trivy_scanner.invoke, {"image_name": base_image})
#             target_res, base_res = json.loads(future_target.result()), json.loads(future_base.result())

#         if "error" in target_res or "error" in base_res:
#             raise HTTPException(status_code=400, detail=f"Image scanning failed. Target: {target_res.get('error')}, Base: {base_res.get('error')}")
        
#         return [target_res["output_path"], base_res["output_path"]]
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))
@mcp.tool()
async def scan_images(target_image: str, base_image: str):
    """Step 1: Scans the target and base Docker images and returns the actual scan results."""
    try:
        with ThreadPoolExecutor() as executor:
            future_target = executor.submit(trivy_scanner.invoke, {"image_name": target_image})
            future_base = executor.submit(trivy_scanner.invoke, {"image_name": base_image})
            
            # 获取扫描结果
            target_result = future_target.result()
            base_result = future_base.result()
            
            # 解析JSON结果
            target_res = json.loads(target_result)
            base_res = json.loads(base_result)
            
            if "error" in target_res or "error" in base_res:
                raise HTTPException(status_code=400, detail=f"Image scanning失败: Target: {target_res.get('error')}, Base: {base_res.get('error')}")
            
            # 读取实际扫描内容
            def get_scan_content(res):
                if "output_path" in res:
                    with open(res["output_path"], 'r') as f:
                        return json.load(f)
                return res
            
            target_content = get_scan_content(target_res)
            base_content = get_scan_content(base_res)
            
            # 返回实际扫描内容
            return {
                "target_scan": target_content,
                "base_scan": base_content,
                "file_paths": [target_res.get("output_path", ""), base_res.get("output_path", "")]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
# @mcp.tool()
# async def classify_cves(scan_path:List[str]) -> ClassifyResponse:
#     """Step 2: Converts scan results to CSV and classifies CVEs."""
#     try:
#         # This logic is taken directly from your classify_cves_node
#         target_csv_res = json.loads(json_to_csv_converter.invoke({"json_file_path": scan_path[0]}))
#         base_csv_res = json.loads(json_to_csv_converter.invoke({"json_file_path": scan_path[1]}))
#         logging.info(target_csv_res["output_path"])
#         logging.info(base_csv_res["output_path"])
#         classification_result = cve_classifier.invoke({"target_csv_path": target_csv_res["output_path"], "base_csv_path": base_csv_res["output_path"]})
#         logging.info("classification done")

#         return {
#             "type1_cves": classification_result["type1_cves"],
#             "type2_cves": classification_result["type2_cves"],
#             "type3_cves": classification_result["type3_cves_to_analyze"]
#         }
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

@mcp.tool()
async def classify_cves(scan_path: List[dict]) -> ClassifyResponse:  # 改为接受字典列表
    """Step 2: Converts scan results to CSV and classifies CVEs."""
    try:
        # 从字典中提取路径
        target_path = scan_path[0]["image_json_path"][0]  # 取第一个文件的路径
        base_path = scan_path[0]["image_json_path"][1]    # 取第二个文件的路径

        target_csv_res = json.loads(json_to_csv_converter.invoke({"json_file_path": target_path}))
        base_csv_res = json.loads(json_to_csv_converter.invoke({"json_file_path": base_path}))
        logging.info(target_csv_res["output_path"])
        logging.info(base_csv_res["output_path"])

        classification_result = cve_classifier.invoke({
            "target_csv_path": target_csv_res["output_path"],
            "base_csv_path": base_csv_res["output_path"]
        })
        logging.info("classification done")

        return {
            "type1_cves": classification_result["type1_cves"],
            "type2_cves": classification_result["type2_cves"],
            "type3_cves": classification_result["type3_cves_to_analyze"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@mcp.tool()
async def expert_analysis(type_cves: ExpertAnalysisRequest) -> ExpertAnalysisResponse:
    try:
        # 并行处理Type-3 CVEs
        analysis_results = []
        logging.info("init analysis results list")
        if type_cves.type3_cves:
            with ThreadPoolExecutor(max_workers=5) as executor:
                analysis_results = list(executor.map(analyze_single_cve, type_cves.type3_cves))
        
        # 保持原始Type-1/2数据不变，仅添加分析结果
        return {
            "type1_cves": type_cves.type1_cves,
            "type2_cves": type_cves.type2_cves,
            "expert_analysis_results": analysis_results
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )
    
@mcp.tool()
async def generate_report(analysis_result:ReportRequest):
    """Step 4: Generates the final report from all classified CVE data."""
    try:
        # This logic is taken directly from your final_report_node
        final_payload = {"classified_cves": {
            "type1_cves": analysis_result.type1_cves,
            "type2_cves": analysis_result.type2_cves,
            "type3_results": analysis_result.expert_analysis_results
        }}
        report_message = cve_report_generator.invoke(final_payload)
        return {"final_report_message": report_message}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
if __name__ == "__main__":
     mcp.run(transport="streamable-http", mount_path="/mcp")