#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <ctime>

#define BYTETOBINARYPATTERN "%d%d%d%d%d%d%d%d"
#define BYTETOBINARY(byte)  \
  (byte & 0x80 ? 1 : 0), \
  (byte & 0x40 ? 1 : 0), \
  (byte & 0x20 ? 1 : 0), \
  (byte & 0x10 ? 1 : 0), \
  (byte & 0x08 ? 1 : 0), \
  (byte & 0x04 ? 1 : 0), \
  (byte & 0x02 ? 1 : 0), \
  (byte & 0x01 ? 1 : 0)


//using namespace std;

std::string arrayToString(unsigned char* a, int size) {
    int i;
    std::string s;
    for (i = 0; i < size; i++){
        s += a[i];
    }

    return s;
}
std::string shift_bits(std::string s, int n)
{
    std::string k = "";

    for (int i = n; i < s.size(); i++)
        k += s[i];

    for (int i = 0; i < n; i++)
        k += s[i];

    return k;
}
std::string do_xor(std::string s1, std::string s2)
{
    std::string result = "";
    for (int j = 0; j < s1.size(); j++) {
        if (s1[j] != s2[j]) result += '1';
        else result += '0';
    }
    return result;
}
std::string dec_to_bin(int n)
{
    std::string bin = "";
    while (n > 0)
    {
        bin = (char)(n % 2 + '0') + bin;
        n /= 2;
    }
    while (bin.size() < 4)
        bin = '0' + bin;
    return bin;
}
std::string bin_to_Hex(std::string s)
{
    std::string hex = "";
    for (int i = 0; i < s.size(); i += 4)
    {
        std::string k = "";
        for (int j = i; j < i + 4; j++)
            k += s[j];
        if (k == "0000")
            hex += '0';
        else if (k == "0001")
            hex += '1';
        else if (k == "0010")
            hex += '2';
        else if (k == "0011")
            hex += '3';
        else if (k == "0100")
            hex += '4';
        else if (k == "0101")
            hex += '5';
        else if (k == "0110")
            hex += '6';
        else if (k == "0111")
            hex += '7';
        else if (k == "1000")
            hex += '8';
        else if (k == "1001")
            hex += '9';
        else if (k == "1010")
            hex += 'A';
        else if (k == "1011")
            hex += 'B';
        else if (k == "1100")
            hex += 'C';
        else if (k == "1101")
            hex += 'D';
        else if (k == "1110")
            hex += 'E';
        else if (k == "1111")
            hex += 'F';
    }
    return hex;
}


class IRoundKeysGenEnc{
public:
    virtual std::vector<std::string> GenerateRoundKeys(std::string key64) = 0;
    virtual std::string Encrypt(std::string text, std::string key, int counter) = 0;
};

class ICipher{
public:
    virtual std::string Cipher(std::string text, std::vector<std::string> keys) = 0;
};

class Fiestel : public ICipher{
    IRoundKeysGenEnc *round_keys_enc;
public:
    Fiestel(IRoundKeysGenEnc &keys) {
        this -> round_keys_enc = &keys;
    };

    std::string Cipher(std::string text, std::vector<std::string> keys){
        std::string leftText, rightText;

        for (int i = 0; i < 32; i++){
            leftText += text[i];
        }

        for (int i = 32; i < 64; i++){
            rightText += text[i];
        }

        std::string L_32[16], R_32[16];
        std::string R_48[16];
        std::string P_R[16];

        P_R[0] = round_keys_enc->Encrypt(rightText, keys[0], 0);

        L_32[0] = rightText;
        R_32[0] = "";
        R_32[0] = do_xor(P_R[0], leftText);


        for (int i = 1; i < 16; i++){
            L_32[i] = R_32[i];
            R_48[i] = "";
            P_R[i] = round_keys_enc->Encrypt(R_32[i], keys[i], i);

            L_32[i] = R_32[i - 1];
            R_32[i] = "";
            R_32[i] = do_xor(P_R[i], L_32[i - 1]);
        }

        std::string enc_bin, RL;

        RL = R_32[15] + L_32[15];


        return RL;

    };

};

class PSPermutations{
    int Sbox[8][4][16] = {
            {
                    { 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },
                    { 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },
                    { 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
                    { 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }
            },
            {
                    { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
                    { 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },
                    { 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
                    { 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 }
            },
            {
                    { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
                    { 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
                    { 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
                    { 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }
            },
            {
                    { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
                    { 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },
                    { 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
                    { 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }
            },
            {
                    { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
                    { 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },
                    { 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
                    { 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }
            },
            {
                    { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
                    { 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },
                    { 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
                    { 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }
            },
            {
                    { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1 },
                    { 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6 },
                    { 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 },
                    { 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 }
            },
            {
                    { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
                    { 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },
                    { 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
                    { 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
            }
    };

    const int P[32] = { 	16 ,7  ,20 ,21 ,
                           29 ,12 ,28 ,17 ,
                           1  ,15 ,23 ,26 ,
                           5  ,18 ,31 ,10 ,
                           2  ,8  ,24 ,14 ,
                           32 ,27 ,3  ,9  ,
                           19 ,13 ,30 ,6  ,
                           22 ,11 ,4  ,25 };

public :
    std::string sBlockPermutation(std::string s, int k)
    {
        int dec1 = 0, dec2 = 0, pwr = 0;
        dec1 = (int)(s[0] - '0') * 2 + (int)(s[5] - '0');
        for (int i = s.size() - 2; i >= 1; i--)
        {
            dec2 += (int)(s[i] - '0') * pow(2, pwr++);
        }

        return dec_to_bin(Sbox[k][dec1][dec2]);
    }

    std::string pBlockPermutation(std::string str, int k){
        std::string res;
        res += str[P[k] - 1];
        return res;
    }
};

class DES{
    const int IP_t[64] = { 	58 ,50 ,42 ,34 ,26 ,18 ,10 ,2 ,
                              60 ,52 ,44 ,36 ,28 ,20 ,12 ,4 ,
                              62 ,54 ,46 ,38 ,30 ,22 ,14 ,6 ,
                              64 ,56 ,48 ,40 ,32 ,24 ,16 ,8 ,
                              57 ,49 ,41 ,33 ,25 ,17 ,9  ,1 ,
                              59 ,51 ,43 ,35 ,27 ,19 ,11 ,3 ,
                              61 ,53 ,45 ,37 ,29 ,21 ,13 ,5 ,
                              63 ,55 ,47 ,39 ,31 ,23 ,15 ,7 };

    const int P_1[64] = { 	40 ,8  ,48 ,16 ,56 ,24 ,64 ,32 ,
                             39 ,7  ,47 ,15 ,55 ,23 ,63 ,31 ,
                             38 ,6  ,46 ,14 ,54 ,22 ,62 ,30 ,
                             37 ,5  ,45 ,13 ,53 ,21 ,61 ,29 ,
                             36 ,4  ,44 ,12 ,52 ,20 ,60 ,28 ,
                             35 ,3  ,43 ,11 ,51 ,19 ,59 ,27 ,
                             34 ,2  ,42 ,10 ,50 ,18 ,58 ,26 ,
                             33 ,1  ,41 ,9  ,49 ,17 ,57 ,25 };


class DesPermutations : public IRoundKeysGenEnc{
        PSPermutations psperm;
        const int PC_1[56] = {  57 ,49 ,41 ,33 ,25 ,17 ,9  ,
                                1  ,58 ,50 ,42 ,34 ,26 ,18 ,
                                10 ,2  ,59 ,51 ,43 ,35 ,27 ,
                                19 ,11 ,3  ,60 ,52 ,44 ,36 ,
                                63 ,55 ,47 ,39 ,31 ,23 ,15 ,
                                7  ,62 ,54 ,46 ,38 ,30 ,22 ,
                                14 ,6  ,61 ,53 ,45 ,37 ,29 ,
                                21 ,13 ,5  ,28 ,20 ,12 ,4 };

        int num_leftShift[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 }; // number of bits to shift for each iteration

        const int PC_2[48] = {  14 ,17 ,11 ,24 ,1  ,5  ,
                                3  ,28 ,15 ,6  ,21 ,10 ,
                                23 ,19 ,12 ,4  ,26 ,8  ,
                                16 ,7  ,27 ,20 ,13 ,2  ,
                                41 ,52 ,31 ,37 ,47 ,55 ,
                                30 ,40 ,51 ,45 ,33 ,48 ,
                                44 ,49 ,39 ,56 ,34 ,53 ,
                                46 ,42 ,50 ,36 ,29 ,32 };



        const int Expand[48] = { 	32 ,1  ,2  ,3  ,4  ,5  ,
                                    4  ,5  ,6  ,7  ,8  ,9  ,
                                    8  ,9  ,10 ,11 ,12 ,13 ,
                                    12 ,13 ,14 ,15 ,16 ,17 ,
                                    16 ,17 ,18 ,19 ,20 ,21 ,
                                    20 ,21 ,22 ,23 ,24 ,25 ,
                                    24 ,25 ,26 ,27 ,28 ,29 ,
                                    28 ,29 ,30 ,31 ,32 ,1 };


    public:
    std::vector<std::string> GenerateRoundKeys(std::string key64){
        std::string key56, keyFirstHalf, keySecondHalf;
            for (int i = 0; i < 56; i++)
                key56 += key64[PC_1[i] - 1];

            for (int i = 0; i < 28; i++)
                keyFirstHalf += key56[i];

            for (int i = 28; i < 56; i++)
                keySecondHalf += key56[i];


        std::string leftKey[16], rightKey[16];
            leftKey[0] = shift_bits(keyFirstHalf, num_leftShift[0]);
            rightKey[0] = shift_bits(keySecondHalf, num_leftShift[0]);

            for (int i = 1; i < 16; i++){
                leftKey[i] = shift_bits(leftKey[i-1], num_leftShift[i]);
                rightKey[i] = shift_bits(rightKey[i-1], num_leftShift[i]);
            }

        std::string key48[16], keys56[16];
        std::vector<std::string> keys48;

            for (int i = 0; i < 16; i++){
                keys56[i] = leftKey[i] + rightKey[i];
            }

            for (int i = 0; i < 16; i++) {
                key48[i] = "";
                for (int j = 0; j < 48; j++){
                    key48[i] += keys56[i][PC_2[j] - 1];
                }
                keys48.push_back(key48[i]);
            }


            return keys48;
        }

    std::string Encrypt(std::string text, std::string key, int counter){
        std::string R_48[16], R_xor_K[16], s[16][8], s_1[16], P_R[16];
            for (int i = 0; i < 48; i++){
                R_48[counter] += text[Expand[i] - 1];
            }

            R_xor_K[counter] = do_xor(R_48[counter], key);

            for (int i = 0; i < 48; i += 6){
                for (int j = i; j < i + 6; j++){
                    s[counter][j / 6] += R_xor_K[counter][j];
                }
            }
            s_1[counter] = "";
            for (int i = 0; i < 8; i++){
                s_1[counter] += psperm.sBlockPermutation(s[counter][i], i);
            }

            for (int i = 0; i < 32; i++) {
                P_R[counter] += psperm.pBlockPermutation(s_1[counter], i);
            }
            return P_R[counter];
        }
    };
    DesPermutations dp;
    Fiestel fs{dp};
public:
    std::string EncPermute(std::string text, std::string key){
        std::string IP, RL, enc_bin;
        std::vector<std::string> final_keys;

        for (int i = 0; i < 64; i++){
            IP += text[IP_t[i] - 1];
        }

        final_keys = dp.GenerateRoundKeys(key);
        RL = fs.Cipher(IP, final_keys);

        for (int i = 0; i < 64; i++){
            enc_bin += RL[P_1[i] - 1];
        }
        return bin_to_Hex(enc_bin);
    }


};


int main(){
    std::srand(time(NULL));
    unsigned char text[8], key[8], text64[64], key64[64];
    char key_bin[8][8], text_bin[8][8];
    int ctr1 = 0;
    int ctr2 = 0;

    for (int i = 0; i < 8; i++) {
        text[i] = std::rand()%256;
        ::sprintf(text_bin[i], BYTETOBINARYPATTERN, BYTETOBINARY(text[i]));
    }

    for (int i = 0; i < 8; i++) {
        key[i] = std::rand()%256;
        ::sprintf(key_bin[i], BYTETOBINARYPATTERN, BYTETOBINARY(key[i]));

    }

    for (int i = 0; i < 8; i++){
        for (int j = 0; j < 8; j++){
            key64[ctr1] = key_bin[i][j];
            ctr1++;
        }
    }

    for (int i = 0; i < 8; i++){
        for (int j = 0; j < 8; j++){
            text64[ctr2] = text_bin[i][j];
            ctr2++;
        }
    }

    int keySize = sizeof(key64) / sizeof(unsigned char);
    int textSize = sizeof(text64) / sizeof(unsigned char);

    std::string raw_text = arrayToString(text64, textSize);
    std::string raw_key = arrayToString(key64, keySize);


    DES des;
    std::cout << des.EncPermute(raw_text, raw_key) << std::endl;


    return 0;
}
