package org.wso2.hsm.cryptoprovider.util;

import iaik.pkcs.pkcs11.*;

public class SessionInitiator {
    private static SessionInitiator sessionInitiator;

    private Slot[] slotsWithTokens = null;

    /**
     * Singleton pattern is used in here.
     * Get the default SessionInitiator.
     *
     * @return Instance of a SessionInitiator
     */
    public static SessionInitiator defaultSessionInitiator() {
        if (sessionInitiator == null) {
            sessionInitiator = new SessionInitiator();
        }
        return sessionInitiator;
    }


    private SessionInitiator() {
    }

    /**
     * Initiate a session.
     *
     * @param pkcs11Module : PKCS #11 module.
     * @param userPin      : User PIN of the slot.
     * @param slotNo       : Slot number of the required session
     * @return Instance of a Session.
     */
    public Session initiateSession(Module pkcs11Module, char[] userPin, int slotNo) {
        Session session = null;
        if (slotsWithTokens == null) {
            try {
                slotsWithTokens = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
            } catch (TokenException e) {
                System.out.println("Session initiation error : " + e.getMessage());
            }
        }
        if (slotsWithTokens.length > slotNo) {
            Slot slot = slotsWithTokens[slotNo];
            try {
                Token token = slot.getToken();
                session = token.openSession(Token.SessionType.SERIAL_SESSION,
                        Token.SessionReadWriteBehavior.RW_SESSION, null, null);
                session.login(Session.UserType.USER, userPin);
            } catch (TokenException e) {
                System.out.println("Session initiation error : " + e.getMessage());
            }
        }
        return session;
    }
}
