"""Read-only binary inventory. Run through URA with --trust-script."""
import json
import ura
def main():
    project=ura.current_project()
    print(json.dumps({'binary':project.metadata()['binary'],
                      'functions':[{'address':hex(f.address),'name':f.name} for f in project.functions()]},indent=2))
if __name__=='__main__':main()
