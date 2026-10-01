from security_engine.parser import parse_json_line, parse_nginx_line

def test_nginx_combined_parser():
    e=parse_nginx_line('203.0.113.2 - - [01/Oct/2026:10:11:12 +0800] "GET /home?q=1 HTTP/1.1" 200 123 "-" "Browser/1" 0.025')
    assert (e.source_ip,e.path,e.status,e.method)==('203.0.113.2','/home',200,'GET')
    assert e.request_time==.025

def test_nginx_auth_outcome_inference():
    failed=parse_nginx_line('192.0.2.10 - - [01/Oct/2026:10:11:12 +0800] "POST /login HTTP/1.1" 401 30 "-" "Test"')
    success=parse_nginx_line('192.0.2.10 - - [01/Oct/2026:10:11:13 +0800] "POST /login HTTP/1.1" 200 30 "-" "Test"')
    assert failed.auth_result=='failure' and success.auth_result=='success'

def test_json_whitelists_sensitive_fields():
    e=parse_json_line('{"source_ip":"192.0.2.1","method":"CUSTOM attacker-text","path":"/login?token=secret","referer":"https://user:pass@example.test/start?session=secret","request_id":"token-secret","session_hash":"cookie-secret","cookie":"session-secret","password":"x","status":200}')
    assert e.source_ip=='192.0.2.1'
    assert 'cookie' not in e.model_dump() and 'password' not in e.model_dump()
    assert e.path=='/login' and e.referer=='https://example.test' and e.method=='OTHER'
    assert 'secret' not in e.model_dump_json() and e.session_hash.startswith('sde1_') and len(e.session_hash)==37

def test_parser_error_is_explicit():
    try: parse_nginx_line('not a log')
    except ValueError as exc: assert 'combined format' in str(exc)
    else: assert False
