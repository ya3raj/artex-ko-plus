package server

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
)

// TestSkillZipErrorsLocalized guards the F3b skill_zip.go bundle: every user-facing
// skill-upload error response (fsUploadSkill surfaces these via
// writeErr(400, err.Error()), see server_mgmt.go) must be English, and no zip-method
// display name may stay Chinese. Reverting any of these literals to Chinese fails here.
func TestSkillZipErrorsLocalized(t *testing.T) {
	// Message constants rendered with sample arguments.
	assertEnglishError(t, "errSkillZipParse",
		fmt.Errorf(errSkillZipParse, fmt.Errorf("boom")).Error())
	assertEnglishError(t, "errSkillZipEncrypted",
		fmt.Sprintf(errSkillZipEncrypted, "demo/SKILL.md"))
	assertEnglishError(t, "errSkillZipUnsupported",
		fmt.Sprintf(errSkillZipUnsupported, "LZMA", 14, "demo/SKILL.md"))

	// A non-zip upload must reach the user as a English hint, not a raw stdlib error.
	if _, err := newSkillZipReader([]byte("this is not a zip archive")); err == nil {
		t.Fatal("비-zip 입력은 오류를 반환해야 합니다")
	} else {
		assertEnglishError(t, "newSkillZipReader", err.Error())
		if !strings.Contains(err.Error(), "archive") {
			t.Fatalf("parse error = %q, want '압축 파일' 안내", err.Error())
		}
	}

	// No zip-method display name may carry a Chinese Han ideograph; the two
	// translated ones (AES, unknown fallback) must be English.
	for m, name := range zipMethodNames {
		for _, r := range name {
			if unicode.Is(unicode.Han, r) {
				t.Fatalf("zipMethodNames[%d] = %q 에 중국어 한자가 남아 있습니다", m, name)
			}
		}
	}
	assertEnglishError(t, "zipMethodName(AES)", zipMethodName(zipMethodAES))
	assertEnglishError(t, "zipMethodName(unknown)", zipMethodName(0xffff))
}
