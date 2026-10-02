package errorPages

type ErrorPagesConfig struct {
	Unauthenticated *ErrorPageConfig `json:"unauthenticated" yaml:"unauthenticated"`
	Unauthorized    *ErrorPageConfig `json:"unauthorized" yaml:"unauthorized"`
}

type ErrorPageConfig struct {
	FilePath   string `json:"file_path" yaml:"filePath"`
	RedirectTo string `json:"redirect_to" yaml:"redirectTo"`
}
