class MPTNode:
    def __init__(self, value=None):
        self.value = value
        self.children = {}  # 子节点哈希 -> 子节点

class MerklePatriciaTree:
    def __init__(self):
        self.root = MPTNode()

    def insert(self, key, value):
        key_bytes = bytes(key, 'utf-8')
        self._insert_recursive(self.root, key_bytes, value)

    def _insert_recursive(self, node, key_bytes, value):
        if len(key_bytes) == 0:
            node.value = value
            return

        nibble = key_bytes[0] >> 4  # 获取键字节的高4位作为nibble
        key_bytes = key_bytes[1:]  # 去掉已处理的键字节

        if nibble in node.children:
            child = node.children[nibble]
        else:
            child = MPTNode()
            node.children[nibble] = child

        self._insert_recursive(child, key_bytes, value)

    def get(self, key):
        key_bytes = bytes(key, 'utf-8')
        return self._get_recursive(self.root, key_bytes)

    def _get_recursive(self, node, key_bytes):
        if len(key_bytes) == 0:
            return node.value

        nibble = key_bytes[0] >> 4  # 获取键字节的高4位作为nibble
        key_bytes = key_bytes[1:]  # 去掉已处理的键字节

        if nibble in node.children:
            child = node.children[nibble]
            return self._get_recursive(child, key_bytes)

        return None
mpt = MerklePatriciaTree()

# 插入键值对
mpt.insert("apple", "red")
mpt.insert("banana", "yellow")
mpt.insert("cherry", "red")

# 获取值
value = mpt.get("banana")
print(value)  # 输出: yellow

value = mpt.get("grape")
print(value)  # 输出: None
