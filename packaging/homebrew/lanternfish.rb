# Homebrew formula for Lanternfish. Install directly:
#   brew install --formula https://raw.githubusercontent.com/hatimtoor/lanternfish/main/packaging/homebrew/lanternfish.rb
class Lanternfish < Formula
  desc "Free web security testing toolkit that teaches as it goes (authorized testing only)"
  homepage "https://github.com/hatimtoor/lanternfish"
  version "0.5.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.5.0/lanternfish_v0.5.0_darwin_arm64"
      sha256 "c3b501df6ac67285019d8e6924b77dae6de55d4d5a91ecfdea1e671a34078854"
    end
    on_intel do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.5.0/lanternfish_v0.5.0_darwin_amd64"
      sha256 "b7c6aef9b66fe541b43dab1156417eb99df82c1a78648a27d71b345115ba91ed"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.5.0/lanternfish_v0.5.0_linux_arm64"
      sha256 "ab92b39ab84547c5e39d18eccc0a4b1abffac2b291fc3198c9e9d2203a47aa00"
    end
    on_intel do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.5.0/lanternfish_v0.5.0_linux_amd64"
      sha256 "6970fb5eae177e833251e5de077c02c8cc0ae625e7b86818160e8ca20ca01750"
    end
  end

  def install
    bin.install Dir["lanternfish_*"].first => "lanternfish"
  end

  test do
    assert_match "lanternfish", shell_output("#{bin}/lanternfish version")
  end
end
