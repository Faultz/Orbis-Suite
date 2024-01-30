#pragma once

class Library
{
public:
	static void LoadLibrary(SceNetId Sock);
	static void UnloadLibrary(SceNetId Sock);
	static void ReloadLibrary(SceNetId Sock);
	static void GetLibraryList(SceNetId Sock);
	static void GetPageList(SceNetId Sock);
	static void GetNamedObjectList(SceNetId s);
private:

};
