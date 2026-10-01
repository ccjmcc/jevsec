from security_engine.rules import evaluate_rules

def test_rule_coverage_and_cap():
    f={'requests_per_second':12,'404_ratio':.7,'401_ratio':.5,'403_ratio':.4,'status_4xx':20,'unique_paths':50,'failed_auth_count':9,'auth_failure_then_success':True,'sensitive_path_count':7,'unique_user_agents':1,'request_count':30,'method_counts':{'TRACE':10,'GET':20}}
    rules,risk=evaluate_rules(f)
    ids={r.rule_id for r in rules}
    assert {'high_request_rate','many_404','many_401','many_403','unique_path_enumeration','login_failure_burst','failure_then_success','sensitive_path_sweep','automated_client','unusual_method_mix'} <= ids
    assert risk==100
