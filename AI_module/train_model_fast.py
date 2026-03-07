import subprocess, sys

if __name__=='__main__':
    raise SystemExit(subprocess.call([sys.executable,'trained_model.py','--no-tune','--trees','200']))
