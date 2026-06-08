# Add submodule
git submodule add https://github.com/<organization>/<repository> testlab-enterprise/windows-adversary-plan/resources/payloads/<repository>

# Navigate to submodule, enable sparse checkout
cd testlab-enterprise/windows-adversary-plan/resources/payloads/<repository>
git sparse-checkout init --cone
git sparse-checkout set <folder-name-1> <folder-name-2>
cd ../../../../../