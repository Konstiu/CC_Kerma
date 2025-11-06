import sqlite3
import constants as const
from jcs import canonicalize
import objects
import json

def _get_connection():
    return sqlite3.connect(const.DB_NAME)

def store_object(obj_dict):
    objid = objects.get_objid(obj_dict)
    json = canonicalize(obj_dict)
    if isinstance(json, str):
        json = json.encode('utf-8')

    with _get_connection() as con:
        cur = con.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO objects (id, object) VALUES (?, ?)",
            (objid, json)
        )
        con.commit()
        

def has_object(objid):
    """Check if an object exists in storage"""
    with _get_connection() as con:
        cur = con.cursor()
        cur.execute("SELECT 1 FROM objects WHERE id = ? LIMIT 1", (objid,))
        return cur.fetchone() is not None

def get_object(objid):
    """Retrieve an object by its ID"""
    with _get_connection() as con:
        cur = con.cursor()
        cur.execute("SELECT data FROM objects WHERE id = ?", (objid,))
        row = cur.fetchone()
        if row:
            return json.loads(row[0])
        return None