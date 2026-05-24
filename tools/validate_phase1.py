import os
import glob
import sys
# Ensure repo root is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from dashboard.analysis_engine import ingest_upload
from dashboard.pipeline import run_full_pipeline
import pandas as pd

def find_sample_run():
    base = os.path.join(os.path.dirname(__file__), '..', 'data', 'runs')
    base = os.path.normpath(base)
    if not os.path.isdir(base):
        return None
    for d in os.listdir(base):
        p = os.path.join(base, d)
        if os.path.isdir(p):
            xmls = glob.glob(os.path.join(p, '*.xml'))
            if xmls:
                return xmls[0]
    return None

def main():
    xml = find_sample_run()
    if not xml:
        print('NO_SAMPLE_RUN')
        return
    print('USING', xml)
    events_df, detections_df, behaviors_df, content_hash = ingest_upload(xml, run_id='validate')
    print('EVENTS', len(events_df) if events_df is not None else 0)
    if detections_df is not None and not detections_df.empty:
        before_unmapped = detections_df['mitre_tactic'].isna().sum() if 'mitre_tactic' in detections_df.columns else 0
    else:
        before_unmapped = 0
    print('BEFORE_UNMAPPED_DETECTIONS', before_unmapped)

    ctx = run_full_pipeline(events_df, detections_df, 'validate', {})
    # After: count campaign-level unmapped (campaigns without any mitre ids)
    campaigns = ctx.get('campaigns', [])
    bursts = ctx.get('timeline', [])
    mapped_bursts = sum(1 for b in bursts if b.get('kill_chain_stage') and b.get('kill_chain_stage') != 'Background')
    total_bursts = len(bursts)
    print('BURSTS_TOTAL', total_bursts)
    print('BURSTS_MAPPED', mapped_bursts)
    print('CAMPAIGNS', len(campaigns))
    # tactic distribution from campaigns
    from collections import Counter
    tactics = Counter()
    for c in campaigns:
        for e in c.get('edges', []):
            tactics.update([e.get('to_stage') or e.get('from_stage')])
    print('TACTIC_DISTRIBUTION', dict(tactics))

if __name__ == '__main__':
    main()
