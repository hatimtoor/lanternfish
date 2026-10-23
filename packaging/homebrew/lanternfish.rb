# Homebrew formula for Lanternfish. Install directly:
#   brew install --formula https://raw.githubusercontent.com/hatimtoor/lanternfish/main/packaging/homebrew/lanternfish.rb
class Lanternfish < Formula
  desc "Free web security testing toolkit that teaches as it goes (authorized testing only)"
  homepage "https://github.com/hatimtoor/lanternfish"
  version "0.1.2"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.1.2/lanternfish_v0.1.2_darwin_arm64"
      sha256 "65dc5569ea2ca74784b1a57bbbe2185f16c1751d19c3258bbead36f458dc8f67"
    end
    on_intel do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.1.2/lanternfish_v0.1.2_darwin_amd64"
      sha256 "824dc425e78b41224ea82de654b35e665cbb200d7ff16e58bd9410a738294709"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.1.2/lanternfish_v0.1.2_linux_arm64"
      sha256 "04516b8bce36e42d64b652cbf129187e142bfbae55d243ec605a0acd7fd2ad48"
    end
    on_intel do
      url "https://github.com/hatimtoor/lanternfish/releases/download/v0.1.2/lanternfish_v0.1.2_linux_amd64"
      sha256 "63f7f75981b088bc75548ba51736762a02b37315e6e8168bd510ec3809078208"
    end
  end

  def install
    bin.install Dir["lanternfish_*"].first => "lanternfish"
  end

  test do
    assert_match "lanternfish", shell_output("#{bin}/lanternfish version")
  end
end
