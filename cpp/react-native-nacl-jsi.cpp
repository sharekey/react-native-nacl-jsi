#include <string>
#include <vector>

#include "aes.h"
#include "argon2id.h"
#include "box.h"
#include "constants.h"
#include "random.h"
#include "react-native-nacl-jsi.h"
#include "secretbox.h"
#include "sign.h"
#include "sodium_18.h"

using namespace facebook;

namespace react_native_nacl {
	void install(jsi::Runtime& jsiRuntime) {
		if (sodium_init() == -1) {
			throw jsi::JSError(jsiRuntime, "[react-native-nacl-jsi] sodium_init() failed");
		}

		install_aes(jsiRuntime);
		install_argon2id(jsiRuntime);
		install_box(jsiRuntime);
		install_constants(jsiRuntime);
		install_random(jsiRuntime);
		install_secret_box(jsiRuntime);
		install_sign(jsiRuntime);
	}

	void cleanup() {
	}
}
