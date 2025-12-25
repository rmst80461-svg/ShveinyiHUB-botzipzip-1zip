#!/usr/bin/env python3
import os
from dotenv import load_dotenv
from utils.database import init_db

load_dotenv()

if __name__ == '__main__':
    init_db()
    print('Database initialized')
