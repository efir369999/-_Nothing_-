"""HADES - God of Storage. SQLite and DAG."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from database import *
from dag_storage import *
