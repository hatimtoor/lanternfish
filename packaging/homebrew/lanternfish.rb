# Homebrew formula for Lanternfish. Install directly:
#   brew install --formula https://raw.githubusercontent.com/hatimtoor/lanternfish/main/packaging/homebrew/lanternfish.rb
class Lanternfish < Formula
  desc "Free web security testing toolkit that teaches as it goes (authorized testing only)"
  homepage "https://github.com/hatimtoor/lanternfish"
  version "0.4.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.4.0/lanternfish_v0.4.0_darwin_arm64"
      sha256 "1fdd114de8b8451871cbc6fe0f7489e3912de58aff5d3045192762f089e8cadd"
    end
    on_intel do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.4.0/lanternfish_v0.4.0_darwin_amd64"
      sha256 "a771de12701f69b04b2db0d92a725f427578ec5b6d73d3e08a8816f75fd1e13d"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.4.0/lanternfish_v0.4.0_linux_arm64"
      sha256 "71e142c80383a84ebd86d4f5e7d3ba716aa5bec74beaee70250debeb2a68f63f"
    end
    on_intel do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.4.0/lanternfish_v0.4.0_linux_amd64"
      sha256 "c9aa8d27e424845c87562e9ed6b0cd290948e62e66cda560809792d91946addf"
    end
  end

  def install
    bin.install Dir["lanternfish_*"].first => "lanternfish"
  end

  test do
    assert_match "lanternfish", shell_output("#{bin}/lanternfish version")
  end
end
