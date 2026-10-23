# Homebrew formula for Lanternfish. Install directly:
#   brew install --formula https://raw.githubusercontent.com/hatimtoor/lanternfish/main/packaging/homebrew/lanternfish.rb
class Lanternfish < Formula
  desc "Free web security testing toolkit that teaches as it goes (authorized testing only)"
  homepage "https://github.com/hatimtoor/lanternfish"
  version "0.2.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.2.0/lanternfish_v0.2.0_darwin_arm64"
      sha256 "91e8eb9c31360edff62d36007aa9a21b126458971b3aff3b66cce5fa1827b297"
    end
    on_intel do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.2.0/lanternfish_v0.2.0_darwin_amd64"
      sha256 "cbc44b696a292855f8350eabf67b128a9fb38495eddcf13805ff2a2cd64e5d3d"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.2.0/lanternfish_v0.2.0_linux_arm64"
      sha256 "28f36764654335aa5cc5a82180aa8a46423bc4ddc9d76add0a438e68a54ed84b"
    end
    on_intel do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.2.0/lanternfish_v0.2.0_linux_amd64"
      sha256 "ca93482d079685699c5eb7d5319cdc9fc70d3eb569c26c88f0dc91cd56f7d652"
    end
  end

  def install
    bin.install Dir["lanternfish_*"].first => "lanternfish"
  end

  test do
    assert_match "lanternfish", shell_output("#{bin}/lanternfish version")
  end
end
