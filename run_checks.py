import subprocess
import sys

def run_command(command, output_file):
    print(f"Running: {' '.join(command)}")
    try:
        with open(output_file, "w") as f:
            result = subprocess.run(
                command,
                stdout=f,
                stderr=subprocess.STDOUT,
                text=True
            )
        print(f"Finished: {' '.join(command)} (Exit Code: {result.returncode})")
        return result.returncode
    except Exception as e:
        print(f"Error running {' '.join(command)}: {e}")
        return 1

def main():
    print("Starting code quality checks...")

    # Define commands and output files
    # Using 'uv run' to ensure we use the project's environment and dependencies
    commands = [
        (["uv", "run", "ruff", "check", "."], "ruff_output.txt"),
        (["uv", "run", "mypy", "src"], "mypy_output.txt"),
        (["uv", "run", "pytest", "-v"], "test_output.txt"),
    ]

    failure = False
    for command, output_file in commands:
        exit_code = run_command(command, output_file)
        if exit_code != 0:
            failure = True

    print("\nChecks completed.")
    if failure:
        print("Some checks failed. Please review the output files.")
        sys.exit(1)
    else:
        print("All checks passed!")
        sys.exit(0)

if __name__ == "__main__":
    main()
