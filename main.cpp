#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <iterator>
#include <sstream>

const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string encode(const std::string &input)
{
    std::string encoded;
    int i = 0;
    int j = 0;
    unsigned char array1[3];
    unsigned char array2[4];

    for (auto& c : input)
    {
        array1[i++] = c;
        if (i == 3)
        {
            array2[0] = (array1[0] & 0xfc) >> 2;
            array2[1] = ((array1[0] & 0x03) << 4) + ((array1[1] & 0xf0) >> 4);
            array2[2] = ((array1[1] & 0x0f) << 2) + ((array1[2] & 0xc0) >> 6);
            array2[3] = array1[2] & 0x3f;

            for(i = 0; i < 4; i++)
                encoded += chars[array2[i]];
            i = 0;
        }
    }

    if (i)
    {
        for(j = i; j < 3; j++)
            array1[j] = '\0';

        array2[0] = (array1[0] & 0xfc) >> 2;
        array2[1] = ((array1[0] & 0x03) << 4) + ((array1[1] & 0xf0) >> 4);
        array2[2] = ((array1[1] & 0x0f) << 2) + ((array1[2] & 0xc0) >> 6);

        for (j = 0; j < i + 1; j++)
            encoded += chars[array2[j]];

        while((i++ < 3))
            encoded += '=';
    }

    return encoded;
}

std::string decode(const std::string &input)
{
    std::string decoded;
    int i = 0;
    int j = 0;
    unsigned char array2[4], array1[3];

    for (auto& c : input)
    {
        if (c == '=')
            break;

        array2[i++] = c;
        if (i == 4)
        {
            for (i = 0; i < 4; i++)
                array2[i] = chars.find(array2[i]);

            array1[0] = (array2[0] << 2) + ((array2[1] & 0x30) >> 4);
            array1[1] = ((array2[1] & 0xf) << 4) + ((array2[2] & 0x3c) >> 2);
            array1[2] = ((array2[2] & 0x3) << 6) + array2[3];

            for (i = 0; i < 3; i++)
                decoded += array1[i];

            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 4; j++)
            array2[j] = 0;

        for (j = 0; j < 4; j++)
            array2[j] = chars.find(array2[j]);

        array1[0] = (array2[0] << 2) + ((array2[1] & 0x30) >> 4);
        array1[1] = ((array2[1] & 0xf) << 4) + ((array2[2] & 0x3c) >> 2);

        for (j = 0; (j < i - 1); j++)
            decoded += array1[j];
    }

    return decoded;
}

std::string xorEncrypt(const std::string &message, const std::string &key)
{
    std::string encrypted_message;
    for (size_t i = 0; i < message.size(); ++i)
        encrypted_message.push_back(message[i] ^ key[i % key.size()]);

    return encrypted_message;
}

int main()
{
    std::string message = "Hello, world!";
    std::string key = "My encryption key";

    // Encrypt the message
    std::string encryptedMessage = xorEncrypt(message, key);

    // Base64 encode the encrypted message
    std::string encodedMessage = encode(encryptedMessage);

    // Decode the Base64 encoded message
    std::string decodedMessage = decode(encodedMessage);

    // Decrypt the decoded message
    std::string decryptedMessage = xorEncrypt(decodedMessage, key);

    std::cout << "Message: " << message << std::endl;
    std::cout << "Key: " << key << std::endl;
    std::cout << "Encoded message: " << encodedMessage << std::endl;
    std::cout << "Decrypted message: " << decryptedMessage << std::endl;

    return 0;
}
