#include <Windows.h>
#include <string>
#include <stdexcept>

/*
    exception type
    0   int
    1   char
    2   std::exception
    ... DWORD64
*/

int exception(int exception_type) {
    //int a = 0;
    //__try {
    //    *(PDWORD)(nullptr) = -1;
    //    a = 2;
    //}
    //__except (EXCEPTION_EXECUTE_HANDLER) {
    //    printf("-----------\n");
    //    getchar();
    //    a = 1;
    //}
    try {
        switch (exception_type) {
        case 0:
            throw 0;
        case 1:
            throw '1';
        case 2:
            throw std::exception("2");
        case 3:
        {
            std::string s = "foo";
            s.at(10);
        }
        default:
            throw (DWORD64)-1;
        }
        return 0;
    }
    catch (int val) {
        printf("exception code = %d\n", val);
        return val;
    }
    catch (char val) {
        printf("exception code = %c\n", val);
        return val - '0';
    }
    catch (const std::out_of_range& e) {
        printf("%s\n", e.what());
        return 3;
    }
    catch (std::exception val) {
        printf("exception code = %s\n", val.what());
        return 2;
    }
    catch (...) {
        printf("exception catched!!\n");
        return 0;
    }
    //return a;
}