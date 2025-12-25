import os
from typing import Optional

class KnowledgeBase:
    def __init__(self):
        self.data_dir = 'data/knowledge_base'
        self.knowledge = {}
        self._load_knowledge()
    
    def _load_knowledge(self):
        """Load knowledge base files"""
        if os.path.exists(self.data_dir):
            for filename in os.listdir(self.data_dir):
                if filename.endswith('.txt'):
                    filepath = os.path.join(self.data_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            category = filename.replace('.txt', '')
                            self.knowledge[category] = f.read()
                    except Exception:
                        pass

kb = KnowledgeBase()
