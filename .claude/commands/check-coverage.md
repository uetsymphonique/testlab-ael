Run the technique coverage check against a scope file and report gaps.

## Steps

1. Ask the user: which scope — Scenario 1 (Crimeware) or Scenario 2 (PRC Espionage)? Which folder or Phase files to check?
2. Run from `testlab-enterprise/mitre-outline/`:

> using venv python from root of project: ../../venv/Scripts/python

```powershell
# Check a whole attack path folder
python check.py --scope "Scenario 1.md" --folder ../windows-adversary-plan/Emulation_Plan/<path>

# Check specific Phase files
python check.py --scope "Scenario 1.md" "../windows-adversary-plan/Emulation_Plan/<path>/Phase N.md"

# Reset all marks before a fresh check
python check.py --reset --scope "Scenario 1.md"
```

3. Report:
   - Techniques now covered (marked in the scope file)
   - Techniques still missing (unchecked in scope)
   - Out-of-scope entries written to `<scope>_out_of_scope.csv`
