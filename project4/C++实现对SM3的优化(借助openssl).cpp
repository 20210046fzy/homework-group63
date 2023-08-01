#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
#include <ctime>
void test_sm3_timing() {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
        return;
    }

    const unsigned int DATA_SIZE = 1000000;  // ����ϣ���ݵĴ�С
    unsigned char* data = new unsigned char[DATA_SIZE];
    memset(data, 'a', DATA_SIZE);

    const EVP_MD* md = EVP_sm3();
    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        std::cerr << "Failed to initialize SM3 hash" << std::endl;
        EVP_MD_CTX_free(ctx);
        delete[] data;
        return;
    }

    // ��ʼ��ʱ
    clock_t start = clock();

    // ���¹�ϣ��״̬
    if (EVP_DigestUpdate(ctx, data, DATA_SIZE) != 1) {
        std::cerr << "Failed to update hash" << std::endl;
        EVP_MD_CTX_free(ctx);
        delete[] data;
        return;
    }

    // ��ɹ�ϣ����
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        std::cerr << "Failed to finalize hash" << std::endl;
        EVP_MD_CTX_free(ctx);
        delete[] data;
        return;
    }

    clock_t end = clock();
    double total_time = ((double)(end - start)) / CLOCKS_PER_SEC;

    std::cout << "����ʱ��: " << total_time << " ��" << std::endl;

    EVP_MD_CTX_free(ctx);
    delete[] data;
}

int main() {
    OpenSSL_add_all_digests();
    test_sm3_timing();
    EVP_cleanup();
    return 0;
}