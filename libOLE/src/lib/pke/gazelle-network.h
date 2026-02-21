/**
 * @file gazelle-network.h  --  Provides an API for sending and receiving objects using cryptoTools channels.
 */

#ifndef LBCRYPTO_GAZELLE_NETWORK_H
#define LBCRYPTO_GAZELLE_NETWORK_H

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Log.h>

#include "../../../../cryptoTools/Network/Channel.h"
// #include "../../../../cryptoTools/Network/Endpoint.h"
// #include "../../../../cryptoTools/Network/IOService.h"

#include <iostream>
#include <fstream>
#include <iterator>

#include "bfv.h"

// #include "stringbuffer.h"
// #include "writer.h"

using namespace osuCryptoNew;

namespace lbcrypto
{
    // ---- helpers ----

    // Raw pointer T*
    template <typename T>
    inline void async_send_limb_copy(osuCrypto::Channel &chl, const T *ptr, u64 count)
    {
        static_assert(std::is_trivially_copyable<T>::value, "limb element must be POD");
        chl.asyncSendCopy(reinterpret_cast<const void *>(ptr), count * sizeof(T));
    }

    // std::vector<T>
    template <typename T>
    inline void async_send_limb_copy(osuCrypto::Channel &chl, const std::vector<T> &v, u64 /*count*/)
    {
        static_assert(std::is_trivially_copyable<T>::value, "limb element must be POD");
        chl.asyncSendCopy(reinterpret_cast<const void *>(v.data()),
                          static_cast<u64>(v.size()) * sizeof(T));
    }

    // T* (raw pointer)
    template <typename T>
    inline void recv_limb(osuCrypto::Channel &chl, T *ptr, u64 count)
    {
        static_assert(std::is_trivially_copyable<T>::value, "limb element must be POD");
        chl.recv(reinterpret_cast<void *>(ptr), count * sizeof(T));
    }

    // std::vector<T>
    template <typename T>
    inline void recv_limb(osuCrypto::Channel &chl, std::vector<T> &v, u64 count)
    {
        static_assert(std::is_trivially_copyable<T>::value, "limb element must be POD");
        if (v.size() != count)
            v.resize(static_cast<size_t>(count));
        chl.recv(reinterpret_cast<void *>(v.data()), v.size() * sizeof(T));
    }

    // T* (raw pointer)
    template <typename T>
    inline void send_limb(osuCrypto::Channel &chl, const T *ptr, u64 count)
    {
        static_assert(std::is_trivially_copyable<T>::value, "limb element must be POD");
        chl.send(reinterpret_cast<const void *>(ptr), count * sizeof(T));
    }

    // std::vector<T>
    template <typename T>
    inline void send_limb(osuCrypto::Channel &chl, const std::vector<T> &v, u64 count)
    {
        static_assert(std::is_trivially_copyable<T>::value, "limb element must be POD");
        // assume v.size() == count; if not, either assert or only send first count elems
        chl.send(reinterpret_cast<const void *>(v.data()),
                 static_cast<u64>(v.size()) * sizeof(T));
    }

    /** Ciphertexts **/

    // WARNING: will block until the other party calls receiveCiphertext
    template <typename DCRTPoly>
    void sendCiphertext(const DCRT_Ciphertext<DCRTPoly> &ct, osuCrypto::Channel &chl)
    {
        constexpr ui32 phim = DCRT_Ciphertext<DCRTPoly>::phim;
        constexpr ui32 numLimbs = DCRT_Ciphertext<DCRTPoly>::numLimbs;

        for (ui32 i = 0; i < numLimbs; ++i)
        {
            send_limb(chl, ct.a.vals[i], static_cast<u64>(phim));
            send_limb(chl, ct.b.vals[i], static_cast<u64>(phim));
        }
    }

    // WARNING: Must ensure input ct life extends until data is sent

    template <typename DCRTPoly>
    void asyncSendCiphertext(const DCRT_Ciphertext<DCRTPoly> &ct, osuCrypto::Channel &chl)
    {
        const ui32 phim = DCRT_Ciphertext<DCRTPoly>::phim;
        const ui32 numLimbs = DCRT_Ciphertext<DCRTPoly>::numLimbs;
        for (ui32 i = 0; i < numLimbs; i++)
        {
            chl.asyncSend(ct.a.vals[i], phim * 8);
            chl.asyncSend(ct.b.vals[i], phim * 8);
        }
    }

    template <typename DCRTPoly>
    void receiveCiphertext(DCRT_Ciphertext<DCRTPoly> &ct, osuCrypto::Channel &chl)
    {
        constexpr ui32 phim = DCRT_Ciphertext<DCRTPoly>::phim;
        constexpr ui32 numLimbs = DCRT_Ciphertext<DCRTPoly>::numLimbs;

        for (ui32 i = 0; i < numLimbs; ++i)
        {
            // A
            recv_limb(chl, ct.a.vals[i], static_cast<u64>(phim));
            // B
            recv_limb(chl, ct.b.vals[i], static_cast<u64>(phim));
        }
    }

    // WARNING: will block until the other party calls receiveCiphertext
    // template <typename poly>
    // void sendCiphertext(const Single_Limb_Ciphertext<poly> &ct, osuCrypto::Channel &chl)
    // {
    //     constexpr ui32 phim = Single_Limb_Ciphertext<poly>::phim;
    //     chl.send(ct.a.vals, phim);
    //     chl.send(ct.b.vals, phim);
    // }
    template <typename poly>
    void sendCiphertext(const Single_Limb_Ciphertext<poly> &ct, osuCrypto::Channel &chl)
    {
        constexpr ui32 phim = Single_Limb_Ciphertext<poly>::phim;

        using T = typename std::remove_pointer<decltype(ct.a.vals)>::type;
        static_assert(std::is_trivially_copyable<T>::value,
                      "Single_Limb_Ciphertext limb type must be POD");

        // A limb
        chl.send(reinterpret_cast<const void *>(ct.a.vals),
                 static_cast<u64>(phim) * sizeof(T));

        // B limb
        chl.send(reinterpret_cast<const void *>(ct.b.vals),
                 static_cast<u64>(phim) * sizeof(T));
    }

    template <typename poly>
    void asyncSendCiphertextCopy(const Single_Limb_Ciphertext<poly> &ct, osuCrypto::Channel &chl)
    {
        // constexpr ui32 phim = Single_Limb_Ciphertext<poly>::phim;
        // chl.asyncSendCopy(ct.a.vals, phim);
        // chl.asyncSendCopy(ct.b.vals, phim);
    }

    // WARNING: Must ensure input ct life extends until data is sent
    template <typename poly>
    void asyncSendCiphertext(const Single_Limb_Ciphertext<poly> &ct, osuCrypto::Channel &chl)
    {
        // constexpr ui32 phim = Single_Limb_Ciphertext<poly>::phim;
        // chl.asyncSend(ct.a.vals, phim);
        // chl.asyncSend(ct.b.vals, phim);
    }

    // WARNING: will block until the other party calls sendCiphertext
    // template <typename poly>
    // void receiveCiphertext(Single_Limb_Ciphertext<poly> &ct, osuCrypto::Channel &chl)
    // {
    //     constexpr ui32 phim = Single_Limb_Ciphertext<poly>::phim;
    //     ct.a.zeros();
    //     ct.b.zeros();
    //     chl.recv(ct.a.vals, phim);
    //     chl.recv(ct.b.vals, phim);
    // }
    template <typename poly>
    void receiveCiphertext(Single_Limb_Ciphertext<poly> &ct, osuCrypto::Channel &chl)
    {
        constexpr ui32 phim = Single_Limb_Ciphertext<poly>::phim;

        ct.a.zeros();
        ct.b.zeros();

        // Deduce the element type T from the pointer ct.a.vals
        using T = typename std::remove_pointer<decltype(ct.a.vals)>::type;
        static_assert(std::is_trivially_copyable<T>::value, "limb element must be POD");

        // Receive A limb
        chl.recv(reinterpret_cast<void *>(ct.a.vals),
                 static_cast<u64>(phim) * sizeof(T));

        // Receive B limb
        chl.recv(reinterpret_cast<void *>(ct.b.vals),
                 static_cast<u64>(phim) * sizeof(T));
    }

    // WARNING: will block until the other party calls receiveCiphertext
    // template <typename DCRTPoly>
    // void sendCiphertext(const DCRT_Seeded_Ciphertext<DCRTPoly> &ct, osuCrypto::Channel &chl)
    // {
    //     const ui32 phim = DCRT_Seeded_Ciphertext<DCRTPoly>::phim;
    //     const ui32 numLimbs = DCRT_Seeded_Ciphertext<DCRTPoly>::numLimbs;
    //     chl.send(ct.seed);
    //     for (ui32 i = 0; i < numLimbs; i++)
    //         chl.send(ct.b.vals[i], phim);
    // }

    // ---- fixed function ----
    template <typename DCRTPoly>
    void sendCiphertext(const DCRT_Seeded_Ciphertext<DCRTPoly> &ct, osuCrypto::Channel &chl)
    {
        const ui32 phim = DCRT_Seeded_Ciphertext<DCRTPoly>::phim;
        const ui32 numLimbs = DCRT_Seeded_Ciphertext<DCRTPoly>::numLimbs;

        // send 16-byte seed
        chl.send(reinterpret_cast<const void *>(&ct.seed), sizeof(ct.seed));

        // send limbs
        for (ui32 i = 0; i < numLimbs; ++i)
        {
            send_limb(chl, ct.b.vals[i], static_cast<u64>(phim));
        }
    }

    template <typename DCRTPoly>
    void asyncSendCiphertextCopy(const DCRT_Seeded_Ciphertext<DCRTPoly> &ct, osuCrypto::Channel &chl)
    {
        // const ui32 phim = DCRT_Seeded_Ciphertext<DCRTPoly>::phim;
        // const ui32 numLimbs = DCRT_Seeded_Ciphertext<DCRTPoly>::numLimbs;
        // chl.asyncSendCopy(ct.seed);
        // for (ui32 i = 0; i < numLimbs; i++)
        //     chl.asyncSendCopy(ct.b.vals[i], phim);
    }

    // ---- your function ----
    template <typename DCRTPoly>
    void asyncSendCiphertext(const DCRT_Seeded_Ciphertext<DCRTPoly> &ct, osuCrypto::Channel &chl)
    {
        // const ui32 phim = DCRT_Seeded_Ciphertext<DCRTPoly>::phim;
        // const ui32 numLimbs = DCRT_Seeded_Ciphertext<DCRTPoly>::numLimbs;

        // // send the 16-byte seed (copying variant so ct can go out of scope safely)
        // chl.asyncSendCopy(reinterpret_cast<const void *>(&ct.seed), sizeof(ct.seed));

        // // send each limb
        // for (ui32 i = 0; i < numLimbs; ++i)
        // {
        //     async_send_limb_copy(chl, ct.b.vals[i], static_cast<u64>(phim));
        // }
    }

    // WARNING: will block until the other party calls sendCiphertext
    // template <typename DCRTPoly>
    // void receiveCiphertext(DCRT_Seeded_Ciphertext<DCRTPoly> &ct, osuCrypto::Channel &chl)
    // {
    //     constexpr ui32 phim = DCRT_Seeded_Ciphertext<DCRTPoly>::phim;
    //     constexpr ui32 numLimbs = DCRT_Seeded_Ciphertext<DCRTPoly>::numLimbs;
    //     // ct.b.zeros();
    //     chl.recv(reinterpret_cast<u8 *>(&ct.seed), sizeof(ct.seed));
    //     for (ui32 i = 0; i < numLimbs; i++)
    //     {
    //         // chl.recv(ct.b.vals[i], phim);
    //         recv_limb(chl, ct.b.vals[i], static_cast<u64>(phim));
    //     }
    // }

    // ---- function ----
    template <typename DCRTPoly>
    void receiveCiphertext(DCRT_Seeded_Ciphertext<DCRTPoly> &ct, osuCrypto::Channel &chl)
    {
        constexpr ui32 phim = DCRT_Seeded_Ciphertext<DCRTPoly>::phim;
        constexpr ui32 numLimbs = DCRT_Seeded_Ciphertext<DCRTPoly>::numLimbs;

        // 16-byte seed
        chl.recv(reinterpret_cast<void *>(&ct.seed), sizeof(ct.seed));

        // limbs
        for (ui32 i = 0; i < numLimbs; ++i)
        {
            recv_limb(chl, ct.b.vals[i], static_cast<u64>(phim));
        }
    }

    template <typename CiphertextType>
    void sendCiphertextVector(const std::vector<CiphertextType> &toSend, osuCrypto::Channel &chl)
    {
        // chl.send(reinterpret_cast<const u8 *>(&toSend.size()), sizeof(toSend.size()));
        // for (ui32 i = 0; i < toSend.size(); i++)
        //     sendCiphertext(toSend[i], chl);
    }

    template <typename CiphertextType>
    void receiveCiphertextVector(std::vector<CiphertextType> &toLoad, osuCrypto::Channel &chl, const bool verbose = false)
    {
        // u64 h64 = 0;
        // chl.recv((u8 *)&h64, sizeof(h64));
        // size_t h = static_cast<size_t>(h64);
        // if (verbose)
        //     std::cout << "Receiving ciphertext vector of size " << h << std::endl;
        // toLoad = std::vector<CiphertextType>(h);
        // for (ui32 i = 0; i < h; i++)
        //     receiveCiphertext(toLoad[i], chl);
    }

    template <typename CiphertextType>
    void sendCiphertextMatrix(const std::vector<std::vector<CiphertextType>> &toSend, osuCrypto::Channel &chl)
    {
        // chl.send(toSend.size());
        // chl.send(toSend[0].size());
        // for (ui32 i = 0; i < toSend.size(); i++)
        //     for (ui32 j = 0; j < toSend[0].size(); j++)
        //         sendCiphertext(toSend[i][j], chl);
    }

    template <typename CiphertextType>
    void receiveCiphertextMatrix(std::vector<std::vector<CiphertextType>> &toLoad, osuCrypto::Channel &chl)
    {
        // u64 h64 = 0;
        // chl.recv((u8 *)&h64, sizeof(h64));
        // size_t h = static_cast<size_t>(h64);

        // chl.recv((u8 *)&h64, sizeof(h64));
        // size_t w = static_cast<size_t>(h64);
        // toLoad = std::vector<std::vector<CiphertextType>>(h, std::vector<CiphertextType>(w));
        // for (ui32 i = 0; i < h; i++)
        //     for (ui32 j = 0; j < w; j++)
        //         receiveCiphertext(toLoad[i][j], chl);
    }

    // template<typename CiphertextType>
    // void sendCiphertext4dData(const std::vector<std::vector<std::vector<CiphertextType>>>& toSend, Channel& chl) {
    //     chl.send(toSend.size());
    //     chl.send(toSend[0].size());
    //     chl.send(toSend[0][0].size());
    //     for (ui32 i = 0; i < toSend.size(); i++)
    //         for (ui32 j = 0; j < toSend[0].size(); j++)
    //             for (ui32 k = 0; k < toSend[0][0].size(); k++)
    //                 sendCiphertext(toSend[i][j][k], chl);
    // }

    // template<typename CiphertextType>
    // void receiveCiphertext4dData(std::vector<std::vector<std::vector<CiphertextType>>>& toLoad, Channel& chl) {
    //     size_t h; chl.recv(h);
    //     size_t w; chl.recv(w);
    //     size_t d; chl.recv(d);
    //     toLoad = std::vector<std::vector<std::vector<CiphertextType>>>(h,
    //         std::vector<std::vector<CiphertextType>>(w, std::vector<CiphertextType>(d)));
    //     for (ui32 i = 0; i < h; i++)
    //         for (ui32 j = 0; j < w; j++)
    //             for (ui32 k = 0; k < d; k++)
    //                 receiveCiphertext(toLoad[i][j][k], chl);
    // }

    /** DCRT Poly **/

    // WARNING: will block until the other party calls receiveCiphertext
    // template <typename DCRTPoly>
    // void sendDCRTPoly(const DCRTPoly &input, osuCrypto::Channel &chl)
    // {
    //     constexpr ui32 phim = DCRTPoly::phim;
    //     constexpr ui32 numLimbs = DCRTPoly::numLimbs;
    //     for (ui32 i = 0; i < numLimbs; i++)
    //         chl.send(input.vals[i], phim);
    // }

    // // WARNING: will block until the other party calls sendCiphertext
    // template <typename DCRTPoly>
    // void receiveDCRTPoly(const DCRTPoly &input, osuCrypto::Channel &chl)
    // {
    //     constexpr ui32 phim = DCRTPoly::phim;
    //     constexpr ui32 numLimbs = DCRTPoly::numLimbs;
    //     for (ui32 i = 0; i < numLimbs; i++)
    //         chl.recv(input.vals[i], phim);
    // }

    template <typename DCRTPoly>
    void sendDCRTPoly(const DCRTPoly &input, osuCrypto::Channel &chl)
    {
        constexpr ui32 phim = DCRTPoly::phim;
        constexpr ui32 numLimbs = DCRTPoly::numLimbs;

        for (ui32 i = 0; i < numLimbs; ++i)
        {
            send_limb(chl, input.vals[i], static_cast<u64>(phim));
        }
    }

    // WARNING: will block until the other party calls sendDCRTPoly
    template <typename DCRTPoly>
    void receiveDCRTPoly(DCRTPoly &output, osuCrypto::Channel &chl) // <-- non-const
    {
        constexpr ui32 phim = DCRTPoly::phim;
        constexpr ui32 numLimbs = DCRTPoly::numLimbs;

        for (ui32 i = 0; i < numLimbs; ++i)
        {
            recv_limb(chl, output.vals[i], static_cast<u64>(phim));
        }
    }

    // // WARNING: will block until the other party calls receiveCiphertext
    // template<typename DCRTPoly>
    // void asyncSendDCRTPoly(const DCRTPoly& input, Channel& chl) {
    //     constexpr ui32 phim = DCRTPoly::phim;
    //     constexpr ui32 numLimbs = DCRTPoly::numLimbs;
    //     for (ui32 i = 0; i < numLimbs; i++)
    //         chl.asyncsend(input.vals[i], phim);
    // }

    // // WARNING: will block until the other party calls sendCiphertext
    // template<typename DCRTPoly>
    // void asyncReceiveDCRTPoly(const DCRTPoly& input, Channel& chl) {
    //     constexpr ui32 phim = DCRTPoly::phim;
    //     constexpr ui32 numLimbs = DCRTPoly::numLimbs;
    //     for (ui32 i = 0; i < numLimbs; i++)
    //         chl.asyncrecv(input.vals[i], phim);
    // }

    template <typename PolyType>
    void sendDCRTPolyVector(const std::vector<PolyType> &toSend, osuCrypto::Channel &chl)
    {
        // chl.send(toSend.size());
        // for (ui32 i = 0; i < toSend.size(); i++)
        //     sendDCRTPoly(toSend[i], chl);
    }

    template <typename PolyType>
    void receiveDCRTPolyVector(std::vector<PolyType> &toLoad, osuCrypto::Channel &chl)
    {
        // u64 h64 = 0;
        // chl.recv((u8 *)&h64, sizeof(h64));
        // size_t h = static_cast<size_t>(h64);
        // toLoad = std::vector<PolyType>(h);
        // for (ui32 i = 0; i < h; i++)
        //     receiveDCRTPoly(toLoad[i], chl);
    }

    // template<typename PolyType>
    // void asyncSendDCRTPolyVector(const std::vector<PolyType>& toSend, Channel& chl) {
    //     chl.asyncSend(toSend.size());
    //     for (ui32 i = 0; i < toSend.size(); i++)
    //         asyncSendDCRTPoly(toSend[i], chl);
    // }

    // template<typename PolyType>
    // void asyncreceiveDCRTPolyVector(std::vector<PolyType>& toLoad, Channel& chl) {
    //     size_t h; chl.asyncRecv(h);
    //     toLoad = std::vector<PolyType>(h);
    //     for (ui32 i = 0; i < h; i++)
    //         asyncReceiveDCRTPoly(toLoad[i], chl);
    // }

    template <typename PolyType>
    void sendDCRTPolyMatrix(const std::vector<std::vector<PolyType>> &toSend, osuCrypto::Channel &chl)
    {
        // chl.send(toSend.size());
        // chl.send(toSend[0].size());
        // for (ui32 i = 0; i < toSend.size(); i++)
        //     for (ui32 j = 0; j < toSend[0].size(); j++)
        //         sendDCRTPoly(toSend[i][j], chl);
    }

    template <typename PolyType>
    void receiveDCRTPolyMatrix(std::vector<std::vector<PolyType>> &toLoad, osuCrypto::Channel &chl)
    {
        // u64 h64 = 0;
        // chl.recv((u8 *)&h64, sizeof(h64));
        // size_t h = static_cast<size_t>(h64);
        // chl.recv((u8 *)&h64, sizeof(h64));
        // size_t w = static_cast<size_t>(h64);
        // toLoad = std::vector<std::vector<PolyType>>(h, std::vector<PolyType>(w));
        // for (ui32 i = 0; i < h; i++)
        //     for (ui32 j = 0; j < w; j++)
        //         receiveDCRTPoly(toLoad[i][j], chl);
    }

    template <typename PolyType>
    void sendDCRTPolyFilter(const std::vector<std::vector<std::vector<PolyType>>> &toSend, osuCrypto::Channel &chl)
    {
        // chl.send(toSend.size());
        // chl.send(toSend[0].size());
        // chl.send(toSend[0][0].size());
        // for (ui32 i = 0; i < toSend.size(); i++)
        //     for (ui32 j = 0; j < toSend[0].size(); j++)
        //         for (ui32 k = 0; k < toSend[0][0].size(); k++)
        //             sendDCRTPoly(toSend[i][j][k], chl);
    }

    template <typename PolyType>
    void receiveDCRTPolyFilter(std::vector<std::vector<std::vector<PolyType>>> &toLoad, osuCrypto::Channel &chl)
    {
        // u64 h64 = 0;
        // chl.recv((u8 *)&h64, sizeof(h64));
        // size_t h = static_cast<size_t>(h64);
        // chl.recv((u8 *)&h64, sizeof(h64));
        // size_t w = static_cast<size_t>(h64);
        // chl.recv((u8 *)&h64, sizeof(h64));
        // size_t d = static_cast<size_t>(h64);
        // toLoad =
        //     std::vector<std::vector<std::vector<PolyType>>>(
        //         h, std::vector<std::vector<PolyType>>(
        //                w, std::vector<PolyType>(d)));
        // for (ui32 i = 0; i < h; i++)
        //     for (ui32 j = 0; j < w; j++)
        //         for (ui32 k = 0; k < d; k++)
        //             receiveDCRTPoly(toLoad[i][j][k], chl);
    }

    /** Keys **/

    template <typename DCRTPoly>
    void sendPublicKey(PublicKeyDCRT<DCRTPoly> &pk, osuCrypto::Channel &chl) {
        // sendDCRTPoly(pk.a, chl);
        // sendDCRTPoly(pk.aShoup, chl);
        // sendDCRTPoly(pk.b, chl);
        // sendDCRTPoly(pk.bShoup, chl);
    };

    template <typename DCRTPoly>
    void receivePublicKey(PublicKeyDCRT<DCRTPoly> &pk, osuCrypto::Channel &chl) {
        // receiveDCRTPoly(pk.a, chl);
        // receiveDCRTPoly(pk.aShoup, chl);
        // receiveDCRTPoly(pk.b, chl);
        // receiveDCRTPoly(pk.bShoup, chl);
    };

    template <typename DCRTPoly>
    inline void sendPublicKey(const PublicKeyDCRTSeeded<DCRTPoly> &pk, osuCrypto::Channel &chl)
    {
        static_assert(std::is_trivially_copyable<decltype(pk.seed)>::value, "seed must be POD");
        static_assert(sizeof(pk.seed) == 16, "seed must be 16 bytes");

        chl.send(reinterpret_cast<const void *>(&pk.seed), sizeof(pk.seed));
        sendDCRTPoly(pk.b, chl); // must match your receiveDCRTPoly
    }

    template <typename DCRTPoly>
    inline void receivePublicKey(PublicKeyDCRTSeeded<DCRTPoly> &pk, osuCrypto::Channel &chl)
    {
        static_assert(std::is_trivially_copyable<decltype(pk.seed)>::value, "seed must be POD");
        static_assert(sizeof(pk.seed) == 16, "seed must be 16 bytes");

        chl.recv(reinterpret_cast<void *>(&pk.seed), sizeof(pk.seed));
        receiveDCRTPoly(pk.b, chl);
    }

    template <typename DCRTPoly>
    void sendSecretKey(const SecretKeyDCRT<DCRTPoly> &sk, osuCrypto::Channel &chl) {
        // sendDCRTPoly(sk.s, chl);
        // sendDCRTPoly(sk.sShoup, chl);
    };

    template <typename DCRTPoly>
    void receiveSecretKey(const SecretKeyDCRT<DCRTPoly> &sk, osuCrypto::Channel &chl) {
        // receiveDCRTPoly(sk.s, chl);
        // receiveDCRTPoly(sk.sShoup, chl);
    };

    /** Encoding Input Types **/

    template <typename poly>
    void sendEncodingInput(const poly &toSend, osuCrypto::Channel &chl) {
        // chl.send(toSend.vals, poly::phim);
    };

    template <typename poly>
    void receiveEncodingInput(const poly &toLoad, osuCrypto::Channel &chl)
    {
        // chl.recv(toLoad.vals, poly::phim);
    }

    template <typename T, ui32 numModuli, ui32 phim>
    void sendEncodingInput(const Array2d<T, numModuli, phim> &toSend, osuCrypto::Channel &chl)
    {
        // for (ui32 i = 0; i < numModuli; i++)
        //     chl.send(toSend[i], phim);
    }

    template <typename T, ui32 numModuli, ui32 phim>
    void receiveEncodingInput(const Array2d<T, numModuli, phim> &toLoad, osuCrypto::Channel &chl)
    {
        // for (ui32 i = 0; i < numModuli; i++)
        //     chl.recv(toLoad[i], phim);
    }

}; // namespace lbcrypto ends
#endif
