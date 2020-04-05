// WideTunnel Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// WtClient.h
// WtClient.c のヘッダ

#ifndef	WTCLIENT_H
#define WTCLIENT_H

UINT WtcConnect(WT *wt, WT_CONNECT *connect, SOCKIO **sockio);
UINT WtcConnectEx(WT *wt, WT_CONNECT *connect, SOCKIO **sockio, UINT ver, UINT build);
TSESSION *WtcNewSession(WT *wt, SOCK *s);
void WtcSessionMain(TSESSION *s);
void WtcWaitForSocket(TSESSION *s);
void WtcSessionMainThread(THREAD *thread, void *param);
void WtcRecvFromGate(TSESSION *s);
void WtcInsertSockIosToSendQueue(TSESSION *s);
void WtcSendToGate(TSESSION *s);
bool WtcCheckDisconnect(TSESSION *s);
void WtcStart(WT *wt);
void WtcStop(WT *wt);

#endif	// WTCLIENT_H

