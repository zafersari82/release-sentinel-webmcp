import os
from pathlib import Path
from release_sentinel.organization_checks.auth_boundary_check import main

ROOT=Path(__file__).parents[1]/'src/release_sentinel/demo_fixture'

def test_checker_measures_vulnerable_behavior(monkeypatch):
 monkeypatch.chdir(ROOT/'repository_vulnerable')
 assert main()==1

def test_checker_measures_fixed_behavior(monkeypatch):
 monkeypatch.chdir(ROOT/'repository_fixed')
 assert main()==0
