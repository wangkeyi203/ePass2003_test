#include "pam_test.h"

char *g_strUserPIN;
CK_BBOOL bTrue = TRUE;
CK_ULONG ulModulusBits = MODULUS_BIT_LENGTH;  //MODULUS_BIT_LENGTH;
CK_BYTE subject[] = "Sample RSA Key Pair";
CK_ULONG keyType = CKK_RSA;


CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
CK_ATTRIBUTE pubTemplate[] = {
        {CKA_CLASS,		&pubClass,		sizeof(pubClass)},
        {CKA_KEY_TYPE,		&keyType,		sizeof(keyType)},
        {CKA_SUBJECT,		subject,		sizeof(subject)},
        {CKA_MODULUS_BITS,	&ulModulusBits, sizeof(ulModulusBits)},
        {CKA_ENCRYPT,		&bTrue,			sizeof(bTrue)},
        {CKA_TOKEN,		&bTrue,			sizeof(bTrue)},
        {CKA_WRAP,		&bTrue,			sizeof(bTrue)},
};	// Without specifying CKA_PRIVATE attribute in this case,
// a public key will be created by default.

CK_OBJECT_CLASS priClass	= CKO_PRIVATE_KEY;
CK_ATTRIBUTE priTemplate[] = {
        {CKA_CLASS,		&priClass,	sizeof(priClass)},
        {CKA_KEY_TYPE,		&keyType,	sizeof(keyType)},
        {CKA_SUBJECT,		subject,	sizeof(subject)},
        {CKA_DECRYPT,		&bTrue,		sizeof(bTrue)},
        {CKA_PRIVATE,		&bTrue,		sizeof(bTrue)},
        {CKA_SENSITIVE,		&bTrue,		sizeof(bTrue)},
        {CKA_TOKEN,		&bTrue,		sizeof(bTrue)},
        {CKA_EXTRACTABLE,	&bTrue,		sizeof(bTrue)},
        {CKA_UNWRAP,		&bTrue,		sizeof(bTrue)},
};

CK_MECHANISM keyGenMechanism = {
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        NULL_PTR,
        0
};

CK_MECHANISM ckMechanism = {CKM_RSA_PKCS, NULL_PTR, 0};
CK_BYTE pbMsg[] = "EnterSafe bring you into e-Business time.";

CK_ULONG ulMsgLen =41;

CK_RV Connect(CK_SLOT_ID_PTR pSlot)
{


    CK_RV rv;

    rv = C_OpenSession(
            pSlot,  CKF_RW_SESSION | CKF_SERIAL_SESSION,
            &m_pApplication, NULL_PTR, &m_hSession);
    if(CKR_OK != rv )
    {
        printf("\nCan't Acquire information ,Error Code is 0x%08X\n", rv);
        //delete[] m_pSlotList;
        free(m_pSlotList);
        m_pSlotList = NULL_PTR;
        return rv;
    }
    else
    {
        printf("Success connect to Token\n");
        return rv;
    }
}

CK_RV Login()
{
    char *s;
    s = getpass("You must input user pin before login:");
    g_strUserPIN = s;
    CK_ULONG ulPIN = strlen(g_strUserPIN);
    CK_BYTE_PTR pPIN = (CK_BYTE_PTR)g_strUserPIN;

    CK_RV rv;
    rv = C_Login(m_hSession, CKU_USER, pPIN, ulPIN);

    while(*s != 0)
            *s++ = 0;

    if(CKR_OK != rv)
    {
        printf("\nCan't use your pin login to Token ,Error code 0x%08X\n", rv);
        return rv;
    }
    else
    {
        printf("Success Login to Token\n");
        return rv;
    }
}


