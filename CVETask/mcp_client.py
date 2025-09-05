# # # cve_client.py
# # import asyncio
# # from fastmcp import Client
# # from typing import Dict, List

# # client = Client("mcp_server_granular.py")  # Matches the server name "CVE Task"

# # async def analyze_cve_workflow(target_image: str, base_image: str):
# #     async with client:
# #         try:
# #             # Step 1: Scan images
# #             scan_result = await client.call_tool(
# #                 "scan_images", 
# #                 {
# #                     "target_image": target_image,
# #                     "base_image": base_image
# #                 }
# #             )
# #             print("Scan completed:", scan_result)

# #             # Step 2: Classify CVEs
# #             classify_result = await client.call_tool(
# #                 "classify_cves",
# #                 {
# #                     "target_scan_path": scan_result["target_scan_path"],
# #                     "base_scan_path": scan_result["base_scan_path"]
# #                 }
# #             )
# #             print("Classification completed:", {
# #                 "type1_count": len(classify_result["type1_cves"]),
# #                 "type2_count": len(classify_result["type2_cves"]),
# #                 "type3_count": len(classify_result["type3_cves"])
# #             })

# #             # Step 3: Expert analysis
# #             expert_result = await client.call_tool(
# #                 "expert_analysis",
# #                 {
# #                     "type1_cves": classify_result["type1_cves"],
# #                     "type2_cves": classify_result["type2_cves"],
# #                     "type3_cves": classify_result["type3_cves"]
# #                 }
# #             )
# #             print("Expert analysis completed with", len(expert_result["expert_analysis_results"]), "results")

# #             # Step 4: Generate report
# #             report_result = await client.call_tool(
# #                 "generate_report",
# #                 {
# #                     "type1_cves": expert_result["type1_cves"],
# #                     "type2_cves": expert_result["type2_cves"],
# #                     "expert_analysis_results": expert_result["expert_analysis_results"]
# #                 }
# #             )
# #             print("\nFinal Report:")
# #             print(report_result["final_report_message"])

# #         except Exception as e:
# #             print("Error during CVE analysis:", str(e))

# # if __name__ == "__main__":
# #     # Example usage - replace with your actual target and base images
# #     asyncio.run(analyze_cve_workflow(
# #         target_image="amr-registry.caas.intel.com/intelanalytics/llm-scaler-vllm:0.10.0-b2",
# #         base_image="amr-registry.caas.intel.com/intelanalytics/llm-scaler-platform:25.38.4.1"
# #     ))
# # cve_client.py
# import asyncio
# from fastmcp import Client

# client = Client("mcp_server_granular.py")  # 必须与服务端名称一致

# async def analyze_cve_workflow(target_image: str, base_image: str):
#     async with client:
#         try:
#             # Step 1: 扫描镜像 (注意嵌套结构)
#             scan_result = await client.call_tool(
#                 "scan_images",
#                 {"request": {"target_image": target_image, "base_image": base_image}}  # 关键修正点
#             )
#             print("✅ 扫描完成:", scan_result)

#             # Step 2: 分类CVE (同样需要嵌套)
#             classify_result = await client.call_tool(
#                 "classify_cves",
#                 {"request": {  # 嵌套结构
#                     "target_scan_path": scan_result["target_scan_path"],
#                     "base_scan_path": scan_result["base_scan_path"]
#                 }}
#             )
#             print("✅ 分类完成:", {
#                 "Type1漏洞数": len(classify_result["type1_cves"]),
#                 "Type2漏洞数": len(classify_result["type2_cves"]),
#                 "Type3漏洞数": len(classify_result["type3_cves"])
#             })

#             # Step 3: 专家分析
#             expert_result = await client.call_tool(
#                 "expert_analysis",
#                 {"request": {  # 嵌套结构
#                     "type1_cves": classify_result["type1_cves"],
#                     "type2_cves": classify_result["type2_cves"],
#                     "type3_cves": classify_result["type3_cves"]
#                 }}
#             )
#             print(f"✅ 专家分析完成 (共分析 {len(expert_result['expert_analysis_results'])} 个Type3漏洞)")

#             # Step 4: 生成报告
#             report_result = await client.call_tool(
#                 "generate_report",
#                 {"request": {  # 嵌套结构
#                     "type1_cves": expert_result["type1_cves"],
#                     "type2_cves": expert_result["type2_cves"],
#                     "expert_analysis_results": expert_result["expert_analysis_results"]
#                 }}
#             )
#             print("\n📝 最终报告:")
#             print(report_result["final_report_message"])

#         except Exception as e:
#             print(f"❌ 处理失败: {str(e)}")

# if __name__ == "__main__":
#     # 示例用法 (替换为你的实际镜像名称)
#     asyncio.run(analyze_cve_workflow(
#         # target_image="amr-registry.caas.intel.com/intelanalytics/llm-scaler-vllm:0.10.0-b2",
#         # base_image="amr-registry.caas.intel.com/intelanalytics/llm-scaler-platform:25.38.4.1"
#         target_image="nginx:1.14.2-alpine",
#         base_image="debian:stretch-slim"
#     ))
# cve_client_fixed.py
import asyncio
from fastmcp import Client
from typing import Dict, List

client = Client("mcp_server_granular.py")  # 必须与服务端名称一致

async def analyze_cve_workflow(target_image: str, base_image: str):
    async with client:
        try:
            # Step 1: 扫描镜像
            scan_response = await client.call_tool(
                "scan_images",
                {"request": {"target_image": target_image, "base_image": base_image}}
            )
            scan_result = scan_response.structured_content  # 关键修正：通过structured_content获取结果
            print("✅ [1/4] 镜像扫描完成")
            print(f"   Target扫描路径: {scan_result['target_scan_path']}")
            print(f"   Base扫描路径: {scan_result['base_scan_path']}")

            # Step 2: 分类CVE
            classify_response = await client.call_tool(
                "classify_cves",
                {"request": {
                    "target_scan_path": scan_result["target_scan_path"],
                    "base_scan_path": scan_result["base_scan_path"]
                }}
            )
            classify_result = classify_response.structured_content
            print("✅ [2/4] CVE分类完成")
            print(f"   Type1漏洞数: {len(classify_result['type1_cves'])}")
            print(f"   Type2漏洞数: {len(classify_result['type2_cves'])}") 
            print(f"   Type3漏洞数: {len(classify_result['type3_cves'])}")

            # Step 3: 专家分析
            expert_response = await client.call_tool(
                "expert_analysis",
                {"request": {
                    "type1_cves": classify_result["type1_cves"],
                    "type2_cves": classify_result["type2_cves"],
                    "type3_cves": classify_result["type3_cves"]
                }}
            )
            expert_result = expert_response.structured_content
            print(f"✅ [3/4] 专家分析完成 (处理{len(expert_result['expert_analysis_results'])}个Type3漏洞)")

            # Step 4: 生成报告
            report_response = await client.call_tool(
                "generate_report",
                {"request": {
                    "type1_cves": expert_result["type1_cves"],
                    "type2_cves": expert_result["type2_cves"],
                    "expert_analysis_results": expert_result["expert_analysis_results"]
                }}
            )
            report_result = report_response.structured_content
            print("\n🔍 [4/4] 最终报告:")
            print("="*50)
            print(report_result["final_report_message"])
            print("="*50)

        except Exception as e:
            print(f"\n❌ 流程执行失败: {type(e).__name__}: {str(e)}")
            # 调试用：打印完整的错误上下文
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    # 使用示例
    TARGET_IMAGE = "amr-registry.caas.intel.com/intelanalytics/llm-scaler-vllm:0.10.0-b2"
    BASE_IMAGE = "amr-registry.caas.intel.com/intelanalytics/llm-scaler-platform:25.38.4.1"
    print("🚀 开始CVE分析流程...")
    print(f"   目标镜像: {TARGET_IMAGE}")
    print(f"   基准镜像: {BASE_IMAGE}")
    
    asyncio.run(analyze_cve_workflow(
        target_image=TARGET_IMAGE,
        base_image=BASE_IMAGE
    ))