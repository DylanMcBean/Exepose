import argparse
import logging
import os
import signal
import subprocess
import sched
import time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(message)s')

class FuzzerMonitor:
    def __init__(self, output_dir, fuzzer_stats, max_time_without_finds, check_interval):
        self.output_dir = Path(output_dir)
        self.fuzzer_stats_file = fuzzer_stats
        self.max_time_without_finds = max_time_without_finds
        self.scheduler = sched.scheduler(time.time, time.sleep)
        self.check_interval = check_interval
        self.last_fuzzer_data = {}

    def read_fuzzer_file(self):
        """Efficiently reads the fuzzer stats file."""
        fuzzer_stats_path = self.output_dir / self.fuzzer_stats_file
        fuzzer_stats = {}
        try:
            with fuzzer_stats_path.open("r") as file:
                for line in file:
                    if ":" in line:
                        key, value = line.strip().split(":", 1)
                        fuzzer_stats[key.strip()] = int(value) if value.strip().isdigit() else value.strip()
        except FileNotFoundError:
            logging.error(f"{fuzzer_stats_path} does not exist.")
            return None
        except Exception as e:
            logging.error(f"An error occurred while reading {fuzzer_stats_path}: {e}")
            return None
        return fuzzer_stats

    @staticmethod
    def get_afl_fuzz_pids():
        """Get a list of PIDs for afl-fuzz processes."""
        try:
            pids = subprocess.check_output(["pgrep", "-f", "afl-fuzz"]).decode().split()
            return [int(pid) for pid in pids]
        except subprocess.CalledProcessError:
            return []

    @staticmethod
    def stop_fuzzer():
        """Stop afl-fuzz processes gracefully."""
        pids = FuzzerMonitor.get_afl_fuzz_pids()
        for pid in pids:
            logging.info(f"Stopping afl-fuzz process with PID {pid}")
            os.kill(pid, signal.SIGTERM)

    def check_fuzzer_status(self):
        """Check fuzzer status and schedule next check."""
        fuzzer_data = self.read_fuzzer_file()

        if fuzzer_data is not None:
            time_wo_finds = int(fuzzer_data.get("time_wo_finds", 0))
            if time_wo_finds > self.max_time_without_finds:
                logging.info(f"Time since last new path: {time_wo_finds} seconds. No new paths found. Exiting.")
                self.stop_fuzzer()
                return

            last_find = fuzzer_data.get("last_find", 0)
            curr_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            last_found = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_find)) if last_find else 'N/A'

            corpus = f"{int(fuzzer_data.get('corpus_count', 0)):,}" if 'corpus_count' in fuzzer_data else 'N/A'
            crashes = f"{int(fuzzer_data.get('unique_crashes', 0)):,}" if 'unique_crashes' in fuzzer_data else 'N/A'
            hangs = f"{int(fuzzer_data.get('unique_hangs', 0)):,}" if 'unique_hangs' in fuzzer_data else 'N/A'
            execs = f"{int(fuzzer_data.get('execs_done', 0)):,}" if 'execs_done' in fuzzer_data else 'N/A'
            if self.last_fuzzer_data and last_find != self.last_fuzzer_data.get("last_find"):
                logging.info(f"| {curr_time:<20} | {last_found:<20} | {corpus:<13} | {crashes:<13} | {hangs:<11} | {execs:<13} |")
            elif self.last_fuzzer_data.get("last_find") == None:
                logging.info(f"| {'Current Time':<20} | {'Last Find':<20} | {'Corpus Count':<13} | {'Saved Crashes':<13} | {'Saved Hangs':<11} | {'Execs Done':<13} |")
                logging.info(f"| {curr_time:<20} | {last_found:<20} | {corpus:<13} | {crashes:<13} | {hangs:<11} | {execs:<13} |")
        else:
            logging.debug("Fuzzer stats file not found or unreadable.")

        self.last_fuzzer_data = fuzzer_data
        self.scheduler.enter(self.check_interval, 1, self.check_fuzzer_status)

    def run(self):
        current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        logging.info(f"Current Time: {current_time}, Output Dir: {self.output_dir}, Fuzzer Stats: {self.fuzzer_stats_file}, Max Time Without Finds: {self.max_time_without_finds}, Check Interval: {self.check_interval}")
        
        self.scheduler.enter(10, 1, self.check_fuzzer_status)
        self.scheduler.run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor and manage AFLplusplus fuzzing process based on activity.")
    parser.add_argument("--output-dir", default="/path/to/fuzzer/output", help="Directory for fuzzer output")
    parser.add_argument("--fuzzer-stats", default="fuzzer_stats", help="Fuzzer stats filename")
    parser.add_argument("--max-time-without-finds", type=int, default=3600, help="Max time in seconds without new paths before stopping the fuzzer")
    parser.add_argument("--check-interval", type=int, default=60, help="Interval in seconds between checks on fuzzer status")
    args = parser.parse_args()

    monitor = FuzzerMonitor(args.output_dir, args.fuzzer_stats, args.max_time_without_finds, args.check_interval)
    monitor.run()