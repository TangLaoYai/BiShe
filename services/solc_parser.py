"""合约源码解析服务（模块1）

职责：提取合约名、public/external 函数列表、参数类型、修饰符、行号、函数体。
- config.SOLC_MODE == "vm" 时优先调用虚拟机/WSL 内 solc（当前虚拟机未就绪，默认关闭）
- 始终内置正则解析器作为兜底，保证宿主机独立可运行

输出 ContractInfo 结构（全系统统一）：
{
    "contract_name": str,
    "pragma": str,
    "inherits": [str],
    "functions": [{
        "name": str, "visibility": str,          # public/external/internal/private
        "mutability": str,                       # view/pure/payable/""
        "modifiers": [str],
        "params": [{"name": str, "type": str}],
        "returns": [str],
        "body": str, "line": int,
    }],
}
"""
import re

IDENT = r"[A-Za-z_$][\w$]*"
FUNC_RE = re.compile(r"\bfunction\s+(" + IDENT + r")\s*\(")
SPECIAL_FUNC_RE = re.compile(r"\b(constructor|receive|fallback)\s*\(")
PRAGMA_RE = re.compile(r"\bpragma\s+solidity\s+([^;]+)\s*;")
CONTRACT_RE = re.compile(
    r"\b(?:abstract\s+)?contract\s+(" + IDENT + r")(\s+is\s+([^{;{]+))?")
VISIBILITY_WORDS = ("public", "external", "internal", "private")
MUTABILITY_WORDS = ("view", "pure", "payable")
LOCATION_WORDS = ("memory", "storage", "calldata", "indexed")


def _match_paren(text: str, open_idx: int) -> int:
    """返回与 text[open_idx]=='(' 匹配的 ')' 下标，找不到返回 -1"""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _match_brace(text: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _split_top_level(s: str, sep: str = ",") -> list:
    """按顶层分隔符切分（忽略括号/数组内的分隔符），用于 mapping 等复杂参数"""
    parts, depth, cur = [], 0, []
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def _parse_param(raw: str) -> dict:
    """解析单个参数，如 'uint256 amount' / 'mapping(address => uint256) balances'"""
    raw = raw.strip()
    if raw.startswith("mapping"):
        close = raw.find(">") + 1
        if close <= 0:
            return {"name": "", "type": raw}
        rest = raw[close:].split()
        name = ""
        for tok in rest:
            if tok not in LOCATION_WORDS:
                name = tok
                break
        return {"name": name, "type": raw[:close].replace(" ", "")}
    tokens = raw.split()
    if not tokens:
        return {"name": "", "type": raw}
    ptype = tokens[0]
    name = ""
    for tok in tokens[1:]:
        if tok in LOCATION_WORDS:
            continue
        name = tok
    return {"name": name, "type": ptype}


def _parse_function(text: str, m: re.Match, name: str) -> dict:
    """解析一个函数声明（m 匹配到 'function name(' 或 'constructor('）"""
    line = text.count("\n", 0, m.start()) + 1
    params_open = m.end() - 1
    params_close = _match_paren(text, params_open)
    if params_close < 0:
        return None
    params_raw = text[params_open + 1:params_close]
    params = [_parse_param(p) for p in _split_top_level(params_raw)]

    # 修饰区：参数闭括号之后到第一个 '{' 或 ';'
    brace_idx = text.find("{", params_close)
    semi_idx = text.find(";", params_close)
    if brace_idx < 0 or (0 <= semi_idx < brace_idx):
        header, body = text[params_close + 1:semi_idx if semi_idx > 0 else len(text)], ""
    else:
        header, body = text[params_close + 1:brace_idx], ""
        body_close = _match_brace(text, brace_idx)
        if body_close > 0:
            body = text[brace_idx + 1:body_close]

    visibility, mutability = "", ""
    modifiers = []
    returns_clause = re.sub(r"returns\s*\([^)]*\)", "", header)
    for w in VISIBILITY_WORDS:
        if re.search(rf"\b{w}\b", header):
            visibility = w
            break
    for w in MUTABILITY_WORDS:
        if re.search(rf"\b{w}\b", header):
            mutability = w
            break
    rm = re.search(r"returns\s*\(([^)]*)\)", header)
    returns = [_parse_param(p)["type"] for p in _split_top_level(rm.group(1))] if rm else []
    # 自定义修饰符 = 去掉 visibility/mutability/returns 后的标识符
    rest = re.sub(r"\b(?:public|external|internal|private|view|pure|payable|virtual|override)\b",
                  "", returns_clause)
    for tok in re.findall(IDENT, rest):
        if tok != name:
            modifiers.append(tok)

    return {
        "name": name, "visibility": visibility or "default",
        "mutability": mutability, "modifiers": modifiers,
        "params": params, "returns": returns,
        "body": body, "line": line,
    }


def parse_source(source: str) -> dict:
    """正则解析 Solidity 源码，提取合约名与函数信息（含降级保障，异常时返回空结构）"""
    info = {"contract_name": "", "pragma": "", "inherits": [], "functions": []}
    try:
        pm = PRAGMA_RE.search(source)
        if pm:
            info["pragma"] = pm.group(1).strip()
        cm = CONTRACT_RE.search(source)
        if cm:
            info["contract_name"] = cm.group(1)
            if cm.group(3):
                info["inherits"] = [x.strip() for x in cm.group(3).split(",") if x.strip()]

        seen = set()
        for m in list(FUNC_RE.finditer(source)) + list(SPECIAL_FUNC_RE.finditer(source)):
            fn = _parse_function(source, m, m.group(1))
            if fn is None:
                continue
            key = (fn["name"], fn["line"])
            if key in seen:
                continue
            seen.add(key)
            info["functions"].append(fn)

        # 未显式声明合约名时，用第一个函数名兜底
        if not info["contract_name"] and info["functions"]:
            info["contract_name"] = info["functions"][0]["name"]
        return info
    except Exception:
        return info


def format_params(params: list) -> str:
    """参数列表格式化展示，如 'uint256 amount, address to'"""
    return ", ".join(f"{p['type']} {p['name']}".strip() for p in params)
