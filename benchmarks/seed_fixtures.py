from __future__ import annotations

from core.seed.models import ParsedSeedModule


def build_source_heuristic_module(project_name: str, harness_name: str, task_mode: str) -> ParsedSeedModule:
    is_cjson = "cjson" in project_name.lower() or "cjson" in harness_name.lower()
    is_inih = "inih" in project_name.lower() or "ini" in harness_name.lower()
    if is_cjson:
        if task_mode == "VULN_DISCOVERY":
            code = """
def gen_buffered_realloc_probe() -> bytes:
    payload = b'{"msg":"' + (b"A" * 4096) + b'","nest":[1,2,3],"ok":true}'
    return b"1111" + payload + b"\\x00"

def gen_deep_nesting_probe() -> bytes:
    payload = (b"[" * 256) + b"0" + (b"]" * 256)
    return b"1011" + payload + b"\\x00"

def gen_truncated_escape_probe() -> bytes:
    payload = b'{"path":"\\\\\\\\\\\\\\\\","tail":['
    return b"1110" + payload + b"\\x00"

def gen_delete_object_probe() -> bytes:
    payload = b'{"obj":{"dup":"x","nested":{"arr":[{},{}]}},"text":"' + (b"B" * 512) + b'"}'
    return b"0111" + payload + b"\\x00"
"""
            names = [
                "gen_buffered_realloc_probe",
                "gen_deep_nesting_probe",
                "gen_truncated_escape_probe",
                "gen_delete_object_probe",
            ]
        elif task_mode == "SEED_EXPLORE":
            code = """
def gen_diverse_small_object() -> bytes:
    return b"0001" + b'{"a":1,"b":[true,false,null],"c":"text"}' + b"\\x00"

def gen_array_mix() -> bytes:
    return b"0011" + b'[{"x":1},{"y":[1,2,3]},{"z":"qq"}]' + b"\\x00"

def gen_escaped_strings() -> bytes:
    return b"0101" + b'{"esc":"\\\\n\\\\t\\\\u0041","path":"a/b/c"}' + b"\\x00"

def gen_nested_combo() -> bytes:
    return b"0110" + b'{"root":{"items":[{"id":1},{"id":2},{"id":3}],"flag":false}}' + b"\\x00"
"""
            names = [
                "gen_diverse_small_object",
                "gen_array_mix",
                "gen_escaped_strings",
                "gen_nested_combo",
            ]
        else:
            code = """
def gen_init_object() -> bytes:
    return b"0000" + b'{"hello":"world"}' + b"\\x00"

def gen_init_array() -> bytes:
    return b"0001" + b'[1,2,3]' + b"\\x00"

def gen_init_nested() -> bytes:
    return b"0010" + b'{"a":{"b":[1,true,"x"]}}' + b"\\x00"

def gen_init_string() -> bytes:
    return b"0011" + b'"plain-string"' + b"\\x00"
"""
            names = [
                "gen_init_object",
                "gen_init_array",
                "gen_init_nested",
                "gen_init_string",
            ]
    elif is_inih:
        if task_mode == "VULN_DISCOVERY":
            code = """
def gen_oversized_section_probe() -> bytes:
    return b"[" + (b"A" * 96) + b"]\\nkey=value\\n"

def gen_unterminated_section_probe() -> bytes:
    return b"[" + (b"B" * 140) + b"\\nname=value\\n"

def gen_multiline_realloc_pressure() -> bytes:
    return b"[core]\\nlong=" + (b"C" * 180) + b"\\n    continued=" + (b"D" * 180) + b"\\n"

def gen_duplicate_key_pressure() -> bytes:
    return b"[dup]\\nkey=one\\nkey=two\\nkey:three\\n; trailing comment\\n"
"""
            names = [
                "gen_oversized_section_probe",
                "gen_unterminated_section_probe",
                "gen_multiline_realloc_pressure",
                "gen_duplicate_key_pressure",
            ]
        elif task_mode == "SEED_EXPLORE":
            code = """
def gen_bom_and_comments() -> bytes:
    return b"\\xef\\xbb\\xbf;comment\\n[main]\\nname=value ; inline\\n# other comment\\n"

def gen_no_value_and_colon() -> bytes:
    return b"[features]\\nflag\\npath:/tmp/example\\nempty=\\n"

def gen_multiple_sections() -> bytes:
    return b"[a]\\nx=1\\n[b]\\ny=two\\n[a]\\nz=3\\n"

def gen_stream_like_whitespace() -> bytes:
    return b"  root=value\\n[space section]\\n  folded line\\nkey = spaced value\\n"
"""
            names = [
                "gen_bom_and_comments",
                "gen_no_value_and_colon",
                "gen_multiple_sections",
                "gen_stream_like_whitespace",
            ]
        else:
            code = """
def gen_init_basic_section() -> bytes:
    return b"[section]\\nname=value\\n"

def gen_init_colon_pair() -> bytes:
    return b"[network]\\nhost:localhost\\nport=8080\\n"

def gen_init_comments() -> bytes:
    return b"; comment\\n# another\\n[main]\\nkey=value\\n"

def gen_init_multiline() -> bytes:
    return b"[text]\\nmessage=line1\\n  line2\\n"
"""
            names = [
                "gen_init_basic_section",
                "gen_init_colon_pair",
                "gen_init_comments",
                "gen_init_multiline",
            ]
    else:
        code = """
def gen_seed_1() -> bytes:
    return b"seed-1"

def gen_seed_2() -> bytes:
    return b"seed-2"
"""
        names = ["gen_seed_1", "gen_seed_2"]
    return ParsedSeedModule(code=code.strip() + "\n", function_names=names)


def build_binary_heuristic_module(task_mode: str) -> tuple[str, list[str]]:
    if task_mode == "VULN_DISCOVERY":
        code = """
def gen_realloc_probe() -> bytes:
    return b'{"msg":"' + (b"A" * 4096) + b'","nest":[1,2,3],"ok":true}'

def gen_deeply_nested_probe() -> bytes:
    return (b"[" * 256) + b"0" + (b"]" * 256)

def gen_truncated_probe() -> bytes:
    return b'{"path":"\\\\\\\\\\\\\\\\","tail":['

def gen_delete_object_probe() -> bytes:
    return b'{"obj":{"dup":"x","nested":{"arr":[{},{}]}},"text":"' + (b"B" * 512) + b'"}'
"""
        names = [
            "gen_realloc_probe",
            "gen_deeply_nested_probe",
            "gen_truncated_probe",
            "gen_delete_object_probe",
        ]
    elif task_mode == "SEED_EXPLORE":
        code = """
def gen_diverse_object() -> bytes:
    return b'{"a":1,"b":[true,false,null],"c":"text"}'

def gen_array_mix() -> bytes:
    return b'[{"x":1},{"y":[1,2,3]},{"z":"qq"}]'

def gen_escaped_strings() -> bytes:
    return b'{"esc":"\\\\n\\\\t\\\\u0041","path":"a/b/c"}'

def gen_nested_combo() -> bytes:
    return b'{"root":{"items":[{"id":1},{"id":2},{"id":3}],"flag":false}}'
"""
        names = ["gen_diverse_object", "gen_array_mix", "gen_escaped_strings", "gen_nested_combo"]
    else:
        code = """
def gen_init_object() -> bytes:
    return b'{"hello":"world"}'

def gen_init_array() -> bytes:
    return b'[1,2,3]'

def gen_init_nested() -> bytes:
    return b'{"a":{"b":[1,true,"x"]}}'

def gen_init_string() -> bytes:
    return b'"plain-string"'
"""
        names = ["gen_init_object", "gen_init_array", "gen_init_nested", "gen_init_string"]
    return code.strip() + "\n", names
