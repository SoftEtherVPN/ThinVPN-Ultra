#include <Windows.Foundation.h>
#include <Windows.System.Threading.h>
#include <Windows.ApplicationModel.DataTransfer.h>
#include <wrl/event.h>
#include <stdio.h>
#include <Objbase.h>

using namespace ABI::Windows::Foundation;
using namespace ABI::Windows::System::Threading;
using namespace Microsoft::WRL;
using namespace Microsoft::WRL::Wrappers;
using namespace ABI::Windows::ApplicationModel::DataTransfer;

int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev, char *CmdLine, int CmdShow)
{
	OpenClipboard(NULL);

	EmptyClipboard();

	CloseClipboard();

	// Initialize the Windows Runtime.
	RoInitializeWrapper initialize(RO_INIT_SINGLETHREADED);

	// Get the activation factory for the IThreadPoolTimer interface.
	ComPtr<IClipboardStatics2> clipboard;

	HRESULT hr = GetActivationFactory(HStringReference(RuntimeClass_Windows_ApplicationModel_DataTransfer_Clipboard).Get(), &clipboard);

	if (hr != 0)
	{
		return -1;
	}

	boolean t = false;
	hr = clipboard->IsHistoryEnabled(&t);

	hr = clipboard->ClearHistory(&t);

	OpenClipboard(NULL);

	EmptyClipboard();

	CloseClipboard();

	return 0;
}
