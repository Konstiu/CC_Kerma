import json
import objects

OBJECTID_DB_FILE = "objects.json"
def store_object(obj_dict):
    objid = objects.get_objid(obj_dict)
    # Load existing objects
    object = {}
    try:
        with open(OBJECTID_DB_FILE, 'r') as file:
            object = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    # Add new object (or overwrite if exists)
    object[objid] = obj_dict
   
    print(f"Storing object {objid}")
    # Write back to file
    with open(OBJECTID_DB_FILE, 'w') as file:
        json.dump(object, file, indent=2)
    print(f"Object {objid} stored successfully.")

def has_object(objid):
    """Check if an object exists in storage"""
    try:
        with open(OBJECTID_DB_FILE, 'r') as file:
            objects = json.load(file)
            return objid in objects
    except (json.JSONDecodeError, FileNotFoundError):
        return False

def get_object(objid):
    """Retrieve an object by its ID"""
    try:
        with open(OBJECTID_DB_FILE, 'r') as file:
            objects = json.load(file)
            return objects.get(objid)
    except (json.JSONDecodeError, FileNotFoundError):
        return None

