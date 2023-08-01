import hashlib

def build_merkle_tree(data):
    # 如果数据为空，则返回空列表
    if len(data) == 0:
        return []

    # 如果数据只有一个块，则返回该块的哈希值
    if len(data) == 1:
        return [hashlib.sha256(data[0].encode()).hexdigest()]

    # 构建Merkle Tree的下一层
    next_level = []
    for i in range(0, len(data), 2):
        # 获取左右子节点的哈希值
        left_hash = hashlib.sha256(data[i].encode()).hexdigest()
        right_hash = hashlib.sha256(data[i+1].encode()).hexdigest() if i+1 < len(data) else left_hash

        # 将左右子节点的哈希值合并为父节点的哈希值
        parent_hash = hashlib.sha256((left_hash + right_hash).encode()).hexdigest()
        next_level.append(parent_hash)

    # 递归构建Merkle Tree的下一层
    return build_merkle_tree(next_level)

# 示例数据
data = ['A', 'B', 'C', 'D','E']

# 构建Merkle Tree
merkle_tree = build_merkle_tree(data)

# 输出Merkle Tree的根哈希值
print("Merkle Tree的根哈希值:", merkle_tree[0])
