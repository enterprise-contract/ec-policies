package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/cucumber/godog"
)

type (
	inputFileName  struct{}
	configFileName struct{}
	testStateKey   struct{}
)

const (
	policyInputFilename  = "input.json"
	policyConfigFilename = "policy.json"
)

var (
	//go:embed samples/policy-input-golden-container.json
	sampleGCPolicyInput string
)

type testState struct {
	tempDir   string
	variables map[string]string
	cmd       *exec.Cmd
	report    report
	cliPath   string
}

// Types used for parsing violations and warnings from report
type (
	result struct {
		Message  string                 `json:"msg"`
		Metadata map[string]interface{} `json:"metadata,omitempty"`
	}

	input struct {
		Violations []result `json:"violations"`
		Warnings   []result `json:"warnings"`
	}

	report struct {
		FilePaths []input `json:"filepaths"`
	}
)

func thereIsASampleGCPolicyInput(ctx context.Context) (context.Context, error) {
	ts, err := getTestState(ctx)
	if err != nil {
		return ctx, fmt.Errorf("thereIsASampleGCPolicyInput get test state: %w", err)
	}

	p := path.Join(ts.tempDir, policyInputFilename)
	f, err := os.Create(p)
	if err != nil {
		return ctx, fmt.Errorf("creating %s file: %w", p, err)
	}
	defer f.Close()

	if _, err := f.WriteString(sampleGCPolicyInput); err != nil {
		return ctx, fmt.Errorf("writing %s file: %w", p, err)
	}

	return context.WithValue(ctx, inputFileName{}, p), nil
}

func thereIsAPolicyConfig(ctx context.Context, config *godog.DocString) (context.Context, error) {
	ts, err := getTestState(ctx)
	if err != nil {
		return ctx, fmt.Errorf("thereIsAPolicyConfig get test state: %w", err)
	}

	p := path.Join(ts.tempDir, policyConfigFilename)
	f, err := os.Create(p)
	if err != nil {
		return ctx, fmt.Errorf("creating %s file: %w", p, err)
	}
	defer f.Close()

	content := replaceVariables(config.Content, ts.variables)

	if _, err := f.WriteString(content); err != nil {
		return ctx, fmt.Errorf("writing %s file: %w", p, err)
	}

	return context.WithValue(ctx, configFileName{}, p), nil
}

func validateInputWithPolicyConfig(ctx context.Context) (context.Context, error) {
	ts, err := getTestState(ctx)
	if err != nil {
		return ctx, fmt.Errorf("validateInputWithPolicyConfig get test state: %w", err)
	}

	input, ok := ctx.Value(inputFileName{}).(string)
	if !ok {
		return ctx, fmt.Errorf("input file %q not found", input)
	}

	config, ok := ctx.Value(configFileName{}).(string)
	if !ok {
		return ctx, fmt.Errorf("config file %q not found", config)
	}

	cmd := exec.Command(
		ts.cliPath, "validate", "input", "--file", input, "--policy", config, "--strict=false")
	cmd.Dir = ts.tempDir

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return ctx, fmt.Errorf("running ec validate input: %w\n%s", err, stderr.String())
	}

	ts.cmd = cmd

	var r report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		return ctx, fmt.Errorf("unmarshalling report: %w", err)
	}
	ts.report = r

	return setTestState(ctx, ts), nil
}

func thereShouldBeNoViolationsInTheResult(ctx context.Context) error {
	ts, err := getTestState(ctx)
	if err != nil {
		return fmt.Errorf("reading test state: %w", err)
	}

	for _, filepath := range ts.report.FilePaths {
		if len(filepath.Violations) != 0 {
			return errors.New(prettifyResults("expected no violations, got:", filepath.Violations))
		}
	}

	return nil
}

func thereShouldBeNoWarningsInTheResult(ctx context.Context) error {
	ts, err := getTestState(ctx)
	if err != nil {
		return fmt.Errorf("reading test state: %w", err)
	}

	for _, filepath := range ts.report.FilePaths {
		if len(filepath.Warnings) != 0 {
			return errors.New(prettifyResults("expected no warnings, got:", filepath.Warnings))
		}
	}

	return nil
}

func prettifyResults(msg string, results []result) string {
	for _, violation := range results {
		code := violation.Metadata["code"].(string)
		msg += fmt.Sprintf("\n\t%s:\t%s", code, violation.Message)
	}
	return msg
}

func replaceVariables(content string, variables map[string]string) string {
	for name, value := range variables {
		re := regexp.MustCompile(`\$` + name + `\b`)
		content = re.ReplaceAllString(content, value)
	}
	return content
}

func setupScenario(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
	tempDir, err := os.MkdirTemp("", "ec-policies-")
	if err != nil {
		return ctx, fmt.Errorf("setting up scenario: %w", err)
	}

	gitroot, err := guessGitRoot()
	if err != nil {
		return ctx, fmt.Errorf("getting gitroot: %w", err)
	}

	ts := testState{
		cliPath: filepath.Join(gitroot, "acceptance/bin/ec"),
		tempDir: tempDir,
		variables: map[string]string{
			"GITROOT": gitroot,
		},
	}

	return setTestState(ctx, ts), nil
}

func tearDownScenario(ctx context.Context, sc *godog.Scenario, _ error) (context.Context, error) {
	// Purposely ignore errors here to prevent a tear down error to mask a test error.
	ts, _ := getTestState(ctx)

	if ts.tempDir != "" {
		_ = os.RemoveAll(ts.tempDir)
	}
	return ctx, nil
}

func getTestState(ctx context.Context) (testState, error) {
	ts, ok := ctx.Value(testStateKey{}).(testState)
	if !ok {
		return testState{}, errors.New("test state not set")
	}
	return ts, nil
}

func setTestState(ctx context.Context, ts testState) context.Context {
	return context.WithValue(ctx, testStateKey{}, ts)
}

// guessGitRoot looks for a directory containing a .git directory. It starts from the current
// working dirctory and walks up the directory tree.
func guessGitRoot() (string, error) {
	startingPath, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("cannot get current working directory: %w", err)
	}

	for path := startingPath; path != "/"; path = filepath.Dir(path) {
		gitpath := filepath.Join(path, ".git")
		if _, err := os.Stat(gitpath); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("git root not found in %s", startingPath)
}

func InitializeScenario(sc *godog.ScenarioContext) {
	sc.Before(setupScenario)

	sc.Step("^there is a sample golden-container policy input$", thereIsASampleGCPolicyInput)
	sc.Step(`^there is a policy config$`, thereIsAPolicyConfig)
	sc.Step(`^input is validated$`, validateInputWithPolicyConfig)
	sc.Step(`^there should be no violations in the result$`, thereShouldBeNoViolationsInTheResult)
	sc.Step(`^there should be no warnings in the result$`, thereShouldBeNoWarningsInTheResult)

	sc.After(tearDownScenario)
}

func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"features"},
			TestingT: t, // Testing instance that will run subtests.
		},
	}

	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}
