from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput


def send_transaction(priv_key_hex: str, address_to: str, amount_btc: float):
    setup('testnet')  # 设置为比特币测试网络

    # 创建交易输入
    txin = TxInput('UtxoTransactionId', 0)

    # 创建交易输出
    txout = TxOutput(to_address=address_to, value=int(amount_btc * 1e8))

    # 构建交易
    tx = Transaction([txin], [txout])
    tx.sign_input(0, priv_key_hex)

    # 发送交易到比特币测试网络
    tx_hex = tx.serialize()
    print("Transaction Hex: ", tx_hex)

    # 在这里你可以使用比特币测试网络的API将交易广播到网络,例如使用api.tokenized.cc来广播交易


def parse_transaction(tx_hex: str):
    setup('testnet')

    # 从十六进制字符串解析交易
    tx = Transaction.deserialize(tx_hex)

    # 获取交易输入
    for tx_input in tx.inputs:
        print("Input UTXO: ", tx_input.prev_tx_hash.hex())
        print("Input Index: ", tx_input.prev_idx)

    # 获取交易输出
    for i, tx_output in enumerate(tx.outputs):
        value = tx_output.value / 1e8
        print("Output {} Address: ".format(i), tx_output.script_pubkey.address())
        print("Output {} Value (BTC): ".format(i), value)


# 示例用法
private_key_hex = "私钥十六进制字符串"
address_to = "接收地址"
amount_btc = 0.001

# 发送交易
send_transaction(private_key_hex, address_to, amount_btc)

# 解析交易
transaction_hex = "你要解析的交易十六进制字符串"
parse_transaction(transaction_hex)
