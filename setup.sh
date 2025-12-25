#!/bin/bash
echo 'Installing...'
pip install -r requirements.txt
python init_db.py
echo 'Done'
