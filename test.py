# -*- coding: utf-8 -*-
import idaapi
import ida_hexrays
import idautils
import idc
import requests
import json
LLAMA_API_URL = ""
API_KEY = ""
MODEL_NAME = "llama3"

def rename_with_ai(ea):
    if not ida_hexrays.init_hexrays_plugin():
        return
    
    cfunc = ida_hexrays.decompile(ea)
    if not cfunc:
        print(f"[-] 无法反编译 0x{ea:X}")
        return
    pseudocode = str(cfunc)
    prompt = f"""
    分析以下 C++ 伪代码的功能，并推断函数名和变量名的业务含义。
    
    【待分析代码】:
    {pseudocode}
    
    【任务】:
    1. 推断函数名（如 CheckEulaAcceptance）。
    2. 找出代码中所有的变量（如 a1, a2, v3, v4 等），并根据逻辑给出业务含义的命名。
    
    【注意】:
    - 变量 a1 是参数，也要重命名（如 argc）。
    - 变量 a2 是参数，也要重命名（如 argv）。
    
    请严格返回 JSON 格式:
    {{
        "function_name": "CheckEula",
        "variables": {{"a1": "argc", "a2": "argv", "v3": "arg_ptr", "v4": "index"}}
    }}
    """

    headers = { "Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json" }
    
    try:
        print(f"[*] 正在深度分析函数: 0x{ea:X} ...")
        r = requests.post(LLAMA_API_URL, headers=headers, json={
            "model": MODEL_NAME,
            "messages": [
                {"role": "system", "content": "You are a specialized IDA Pro assistant. Only output JSON."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.0
        }, timeout=60)
        
        ai_msg = r.json()['choices'][0]['message']['content']
        print(f"[DEBUG] AI 原文: {ai_msg}")

        start_idx = ai_msg.find('{')
        end_idx = ai_msg.rfind('}') + 1
        result = json.loads(ai_msg[start_idx:end_idx])
        
        new_fname = result.get("function_name")
        if new_fname and "sub_" not in new_fname.lower():
            final_name = f"AI_{new_fname}_{ea:X}"
            idc.set_name(ea, final_name, idc.SN_CHECK | idc.SN_NOWARN)
            print(f"[+] 函数名已更新: {final_name}")

        v_map = result.get("variables", {})
        if isinstance(v_map, dict):
            lvars = cfunc.get_lvars()
            renamed_count = 0
            
            for old_name, new_name in v_map.items():
                clean_new_name = str(new_name).replace(" ", "_").replace("*", "")
                
                for lv in lvars:
                    if lv.name == old_name:
                        lv.name = clean_new_name
                        lv.set_user_name() 
                        renamed_count += 1
                        print(f"    [var] {old_name} -> {clean_new_name}")
                        break
            
            if renamed_count > 0:
                cfunc.get_pseudocode() 
                try:
                    ida_hexrays.hx_save_user_lvar_settings(cfunc.entry_ea, lvars)
                except:
                    pass
                print(f"[+] 成功识别并重命名了 {renamed_count} 个变量")

        v = ida_hexrays.get_widget_vdui(idaapi.get_current_widget())
        if v:
            v.refresh_view(True)
            
    except Exception as e:
        print(f"[-] 脚本执行异常: {str(e)}")

if __name__ == "__main__":
    current_ea = idc.get_screen_ea()
    func = idaapi.get_func(current_ea)
    if func:
        rename_with_ai(func.start_ea)