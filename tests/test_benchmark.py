from security_engine.benchmark import _auc,_metrics

def test_metrics_and_auc():
    rows=[{'label':True,'alert':True,'risk':.9},{'label':False,'alert':True,'risk':.7},{'label':False,'alert':False,'risk':.1}]
    m=_metrics(rows)
    assert m['tp']==1 and m['fp']==1 and m['tn']==1 and m['fn']==0
    assert round(_auc([1,0,0],[.9,.7,.1]),2)==1.0
