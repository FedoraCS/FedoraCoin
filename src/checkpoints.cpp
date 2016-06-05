// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include "checkpoints.h"

#include "main.h"

namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    // How many times we expect transactions after the last checkpoint to
    // be slower. This number is a compromise, as it can't be accurate for
    // every system. When reindexing from a fast disk with a slow CPU, it
    // can be up to 20, while when downloading from a slow network with a
    // fast multicore CPU, it won't be much higher than 1.
    static const double fSigcheckVerificationFactor = 5.0;

    struct CCheckpointData {
        const MapCheckpoints *mapCheckpoints;
        int64 nTimeLastCheckpoint;
        int64 nTransactionsLastCheckpoint;
        uint64 nChainValueLastCheckpoint;
        double fTransactionsPerDay;
    };

    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        (    0, uint256("0x746b18d1b206b817408c355a256a144e740579b6729043d184574642077f2054"))
        (10000, uint256("0x6d3ab190ef96943c4f9e972d581ea399185d0b6fcbd603f9ee03a0883aa9ae1d"))
        (20000, uint256("0xc917ee0a1575b5aa5ca577160a13e64a483c371e026874cd4daa0ca3ab1e0789"))
        (30000, uint256("0x86e335acb647b14329b7e9ad0761e2f8c0fb8e3a85aaba698ef1b94f40784f60"))
        (40000, uint256("0x9736b6307073cf608c6d2a22379d41438f05d26a021fb40c583f7f910923c4b4"))
        (50000, uint256("0xa6e0a09fe644dcbfc8ba436e8f481f1ccfbad2cfb4505588c5e0b4eb37bb6715"))
        (50796, uint256("0xad153188e0bb6d1d0c2e4baf79c7610d5d8744cf93d2986c778382c79862fda6"))
        (51000, uint256("0xa3c6303447a12734830c47ed140b65ea06993adcdfb513510635d3f4aae69bcb")) // credits to Lsrwolf for cracking this block
        (100000, uint256("0xc4eeda4f5e8b0cdeff3d262c419b6a0bbe867c7845b57525b803d666cb11fa0c"))
        (200000, uint256("0x861de6b2a8fb440817700e50c7d3780d747d7c4b2469a86805516ac423fb9336"))
        (300000, uint256("0xa1409ed3ba5241d1cf802833a3e33cc54e401f543274a1fd8f19fb77710dc2d4"))
        (400000, uint256("0xd1ccf535ed9d3e7a6d4bb94084e68f35e8ce759d387e88f605ed550743fae07e"))
        (500000, uint256("0x6938c3aa432e2e8d3bd1c1b1ac303dcc85501935c67cbb2c640d500d2bdee399"))
        (600000, uint256("0x89f68558abc7bcd3f8b967c79b904ffae2cda80a6b68a48883a3c7fbd828ca7d"))
        (700000, uint256("0xf6c4f660a90d8e7674a2ba62c7c1c594c49f43ccdb27473289c4437f8a512f7a "))
        (800000, uint256("0xf325f007e3a4427b54d5b8b9e514ad587d932a480c8a9c8b22c0de354e12309d"))
        (900000, uint256("0x674fb5a00eefe1b29023bd6abc5d15084a885da2992f2f4efa2c0fe32595b935"))
        (1000000, uint256("0xdae50e5e9bdfa667ed48b02cebecb3e7cc217a51d777d71c8afea429a3ac67e4 "))
        (1200000, uint256("0xe9385a7444f0ccc450781f0f5ee558c31c57adbee044afb7d6862d3b49ae4a82"))
        (1250000, uint256("0x93a6bb85284fe4b5e594ea7dbda337274b84a095af0474b438c47435f9349334"))
        (1259838, uint256("0x9bb35f0bcc36939a38dd004033768b6b76e14e4494a041a5816076eedc631b06"))
        (1260223, uint256("0xd8666019ee1f8b8e6bfdb1081311d086aedd847a1618d3260b5e38e9098930e8"))
        ;
    static const CCheckpointData data = {
        &mapCheckpoints,
        1464827776,//1387666072, // * UNIX timestamp of last checkpoint block
        2711570,    // * total number of transactions between genesis and last checkpoint
                    //   (the tx=... number in the SetBestChain debug.log lines)
        130674357365.00001526, // the chain value up to this block (type getchainvalue <height> to find it)
        2000     // * estimated number of transactions per day after checkpoint
    };

    static MapCheckpoints mapCheckpointsTestnet = 
        boost::assign::map_list_of
        (   0, uint256("0x753665c2f084de3a854af1d012f47d86a80a3ada4631e8a1dac198f658ab6224"))
        ;
    static const CCheckpointData dataTestnet = {
        &mapCheckpointsTestnet,
        1391748919,
        0,
        100000000,
        300
    };

    const CCheckpointData &Checkpoints() {
        if (fTestNet)
            return dataTestnet;
        else
            return data;
    }
    uint64 GetLastCheckpointValue()
    {
        if (fTestNet) return 0;
        return data.nChainValueLastCheckpoint;
    }

    bool CheckBlock(int nHeight, const uint256& hash)
    {
        if (fTestNet) return true; // Testnet has no checkpoints
        if (!GetBoolArg("-checkpoints", true))
            return true;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) return true;
        return hash == i->second;
    }

    // Guess how far we are in the verification process at the given block index
    double GuessVerificationProgress(CBlockIndex *pindex) {
        if (pindex==NULL)
            return 0.0;

        int64 nNow = time(NULL);

        double fWorkBefore = 0.0; // Amount of work done before pindex
        double fWorkAfter = 0.0;  // Amount of work left after pindex (estimated)
        // Work is defined as: 1.0 per transaction before the last checkoint, and
        // fSigcheckVerificationFactor per transaction after.

        const CCheckpointData &data = Checkpoints();

        if (pindex->nChainTx <= data.nTransactionsLastCheckpoint) {
            double nCheapBefore = pindex->nChainTx;
            double nCheapAfter = data.nTransactionsLastCheckpoint - pindex->nChainTx;
            double nExpensiveAfter = (nNow - data.nTimeLastCheckpoint)/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore;
            fWorkAfter = nCheapAfter + nExpensiveAfter*fSigcheckVerificationFactor;
        } else {
            double nCheapBefore = data.nTransactionsLastCheckpoint;
            double nExpensiveBefore = pindex->nChainTx - data.nTransactionsLastCheckpoint;
            double nExpensiveAfter = (nNow - pindex->nTime)/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore + nExpensiveBefore*fSigcheckVerificationFactor;
            fWorkAfter = nExpensiveAfter*fSigcheckVerificationFactor;
        }

        return fWorkBefore / (fWorkBefore + fWorkAfter);
    }

    int GetTotalBlocksEstimate()
    {
        if (fTestNet) return 0; // Testnet has no checkpoints
        if (!GetBoolArg("-checkpoints", true))
            return 0;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        if (fTestNet) return NULL; // Testnet has no checkpoints
        if (!GetBoolArg("-checkpoints", true))
            return NULL;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint256& hash = i.second;
            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return NULL;
    }
}
