#include <iostream>
#include <vector>
using namespace std;
vector<uint32_t> generateRoundConstants() {
    vector<uint32_t> roundConstants(32);
    uint32_t alpha = 0x89ABCDF;
    uint32_t beta = 0x01234567;
    for (int i = 0; i < 32; i++) {
        roundConstants[i] = alpha ^ beta;
        alpha = ((alpha << 1) | (alpha >> 31)) ^ roundConstants[i];
        beta = (beta << 1) | (beta >> 31);
    }

    return roundConstants;
}

int main() {
    vector<uint32_t> roundConstants = generateRoundConstants();

    // Output the round constants
    for (int i = 0; i < 32; i++) {
        cout << "Round " << i + 1 << " constant: 0x" << std::hex << roundConstants[i] << std::endl;
    }
    return 0;
}