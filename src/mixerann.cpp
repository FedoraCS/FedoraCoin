//
// Announcement system
//

#include <algorithm>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/foreach.hpp>
#include <map>

#include "mixerann.h"
#include "key.h"
#include "net.h"
#include "ui_interface.h"

using namespace std;

map<uint256, CAnnouncement> mapAnns;
CCriticalSection cs_mapAnns;
string nCurrentMixer;

static const char* pszMainKey = "04a149fda4361bceca937ee587b2994551a0db410762df1056ac61bdf928c5e391544aaa7e4465c3d0ccdeaa61ad7ce2414524141130741f540556b6a3668b9840";
static const char* pszTestKey = "044e194bf39dec808effaf8c0678105fe091eaa3e0411da9116c5a6fea7f58acca905f67cd1600246a7f73c9a6e9ec6f99b173973696c45946c7f1b796aa09e995";

void CUnsignedAnnouncement::SetNull()
{
    nVersion = 1;
    nExpiration = 0;
    nID = 0;
    setRevoke.clear();

    nMinVer = 0;
    nMaxVer = 0;
    setSubVer.clear();

    pReceiveAddressPubKey.clear();
    pSendAddressPubKey.clear();
    pRsaPubKey.clear();
}

std::string CUnsignedAnnouncement::ToString() const
{
    std::string strSetRevoke;
    BOOST_FOREACH(int n, setRevoke)
        strSetRevoke += strprintf("%d ", n);
    std::string strSetSubVer;
    BOOST_FOREACH(std::string str, setSubVer)
        strSetSubVer += "\"" + str + "\" ";

    string recv = HexStr(pReceiveAddressPubKey.begin(), pReceiveAddressPubKey.end());
    string send = HexStr(pSendAddressPubKey.begin(), pSendAddressPubKey.end());
    string rsa = HexStr(pRsaPubKey.begin(), pRsaPubKey.end());
    return strprintf(
        "CAnnouncement(\n"
        "    nVersion                = %d\n"
        "    nExpiration             = %"PRI64d"\n"
        "    nID                     = %d\n"
        "    setRevoke               = %s\n"
        "    nMinVer                 = %d\n"
        "    nMaxVer                 = %d\n"
        "    setSubVer               = %s\n"
        "    pReceiveAddressPubKey   = \"%s\"\n"
        "    pSendAddressPubKey      = \"%s\"\n"
        "    pRsaPubKey              = \"%s\"\n"
        ")\n",
        nVersion,
        nExpiration,
        nID,
        strSetRevoke.c_str(),
        nMinVer,
        nMaxVer,
        strSetSubVer.c_str(),
        recv.c_str(),
        send.c_str(),
        rsa.c_str());
}

void CUnsignedAnnouncement::print() const
{
    printf("%s", ToString().c_str());
}

void CAnnouncement::SetNull()
{
    CUnsignedAnnouncement::SetNull();
    vchMsg.clear();
    vchSig.clear();
}

bool CAnnouncement::IsNull() const
{
    return (nID == 0);
}

uint256 CAnnouncement::GetHash() const
{
    return Hash(this->vchMsg.begin(), this->vchMsg.end());
}
bool CAnnouncement::IsInEffect() const
{
    return (GetAdjustedTime() < nExpiration);
}
bool CAnnouncement::Cancels(const CAnnouncement& ann) const
{
    if (!IsInEffect())
        return false; // this was a no-op before 31403
    return ( nID > ann.nID && setRevoke.count(ann.nID));
}

bool CAnnouncement::AppliesTo(int nVersion, std::string strSubVerIn) const
{
    // TODO: rework for client-version-embedded-in-strSubVer ?
    return (IsInEffect() && nMinVer <= nVersion && nVersion <= nMaxVer &&
            (setSubVer.empty() || setSubVer.count(strSubVerIn)));
}

bool CAnnouncement::AppliesToMe() const
{
    return AppliesTo(PROTOCOL_VERSION, FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, std::vector<std::string>()));
}


bool CAnnouncement::RelayTo(CNode* pnode) const
{
    if (!IsInEffect())
        return false;
    // returns true if wasn't already contained in the set
    if (pnode->setKnownAnns.insert(GetHash()).second)
    {
        if (AppliesTo(pnode->nVersion, pnode->strSubVer))// ||
            //AppliesToMe() ||
           // GetAdjustedTime() < nRelayUntil)
        {
            pnode->PushMessage("announcement", *this);
            return true;
        }
    }
    return false;
}

bool CAnnouncement::CheckSignature() const
{
    CPubKey key(ParseHex(fTestNet ? pszTestKey : pszMainKey));
    if (!key.Verify(Hash(vchMsg.begin(), vchMsg.end()), vchSig))
        return error("CAnnouncement::CheckSignature() : verify signature failed");

    // Now unserialize the data
    CDataStream sMsg(vchMsg, SER_NETWORK, PROTOCOL_VERSION);
    sMsg >> *(CUnsignedAnnouncement*)this;
    return true;
}

bool CAnnouncement::IsAnnouncement() const
{
    return !(pReceiveAddressPubKey.size() <= 1 || pSendAddressPubKey.size() <= 1 || pRsaPubKey.size() <= 1);
}

CAnnouncement CAnnouncement::getAnnouncementByHash(const uint256 &hash)
{
    CAnnouncement retval;
    {
        LOCK(cs_mapAnns);
        map<uint256, CAnnouncement>::iterator mi = mapAnns.find(hash);
        if (mi != mapAnns.end())
            retval = mi->second;
    }
    return retval;
}

bool CAnnouncement::ProcessAnnouncement(bool fThread)
{
    if (!CheckSignature())
        return false;
    if (!IsInEffect())
        return false;

    // alert.nID=max is reserved for if the alert key is
    // compromised. It must have a pre-defined message,
    // must never expire, must apply to all versions,
    // and must cancel all previous
    // alerts or it will be ignored (so an attacker can't
    // send an "everything is OK, don't panic" version that
    // cannot be overridden):
    /*int maxInt = std::numeric_limits<int>::max();
    if (nID == maxInt)
    {
        if (!(
                nExpiration == maxInt &&
                nCancel == (maxInt-1) &&
                nMinVer == 0 &&
                nMaxVer == maxInt &&
                setSubVer.empty() &&
                nPriority == maxInt &&
                strStatusBar == "URGENT: Alert key compromised, upgrade required"
                ))
            return false;
    }*/

    {
        LOCK(cs_mapAnns);
        // Cancel previous alerts
        for (map<uint256, CAnnouncement>::iterator mi = mapAnns.begin(); mi != mapAnns.end();)
        {
            const CAnnouncement& ann = (*mi).second;
            if (Cancels(ann))
            {
                printf("cancelling announcement %d\n", ann.nID);
                //uiInterface.NotifyAlertChanged((*mi).first, CT_DELETED);

                mapAnns.erase(mi++);
            }
            else if (!ann.IsInEffect())
            {
                printf("expiring announcement %d\n", ann.nID);
                //uiInterface.NotifyAlertChanged((*mi).first, CT_DELETED);
                mapAnns.erase(mi++);
            }
            else
                mi++;
        }

        // Check if this announcement has been cancelled
        BOOST_FOREACH(PAIRTYPE(const uint256, CAnnouncement)& item, mapAnns)
        {
            const CAnnouncement& ann = item.second;
            if (ann.Cancels(*this))
            {
                printf("announcement already cancelled by %d\n", ann.nID);
                return false;
            }
        }

        // Add to mapAnns
        mapAnns.insert(make_pair(GetHash(), *this));

        // Choose a random mixer
        int count = 0;
        BOOST_FOREACH(PAIRTYPE(const uint256, CAnnouncement)& item, mapAnns)
        {
            const CAnnouncement& ann = item.second;
            if (ann.IsAnnouncement())
                count++;
        }
        if (count > 0)
        {
            srand(time(NULL));
            int randu = (rand() % count);
            int done = 0;
            BOOST_FOREACH(PAIRTYPE(const uint256, CAnnouncement)& item, mapAnns)
            {
                const CAnnouncement& ann = item.second;
                if (!ann.IsAnnouncement())
                    continue;
                if (done == randu)
                {
                    nCurrentMixer = item.first.GetHex();
                    break;
                }
                done++;
            }
        }
        else
            nCurrentMixer = "";

        // Notify UI and -alertnotify if it applies to me
        /*if (AppliesToMe())
        {
            uiInterface.NotifyAlertChanged(GetHash(), CT_NEW);
            std::string strCmd = GetArg("-alertnotify", "");
            if (!strCmd.empty())
            {
                // Alert text should be plain ascii coming from a trusted source, but to
                // be safe we first strip anything not in safeChars, then add single quotes around
                // the whole string before passing it to the shell:
                std::string singleQuote("'");
                std::string safeStatus = SanitizeString(strStatusBar);
                safeStatus = singleQuote+safeStatus+singleQuote;
                boost::replace_all(strCmd, "%s", safeStatus);

                if (fThread)
                    boost::thread t(runCommand, strCmd); // thread runs free
                else
                    runCommand(strCmd);
            }
        }*/
    }

    printf("accepted announcement %d, AppliesToMe()=%d\n", nID, AppliesToMe());
    return true;
}

