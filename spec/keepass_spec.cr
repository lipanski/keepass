require "spec"
require "../src/keepass"

module Helpers
  def self.parse_simple
    Keepass.parse!("./spec/fixtures/simple.kdbx", "sample")
  end
end

describe Keepass do
  describe ".parse!" do
    describe "with the simple file" do
      it "parses it to a Database object" do
        subject = Helpers.parse_simple
        subject.should be_a(Keepass::Database)
      end

      it "sets the proper metadata" do
        subject = Helpers.parse_simple
        subject.version.should eq("3.1")
      end

      it "sets the proper group values" do
        subject = Helpers.parse_simple
        subject.groups.size.should eq(1)

        group = subject.groups[0]
        group.uuid.should eq("TBThJOxJUTMZdrvssBc8qQ==")
        group.name.should eq("First")
        group.entries.size.should eq(1)
      end

      it "sets the proper entry values" do
        subject = Helpers.parse_simple.groups[0].entries[0]
        subject.uuid.should eq("vuDnmEkxpZnMJshEgFs/sA==")
        subject.title.should eq("test")
        subject.url.should eq("http://www.example.com")
        subject.user_name.should eq("user")
        subject.password.should eq("pass")
        subject.notes.should eq("notes")
      end

      it "sets the proper entry timestamps and usage count" do
        subject = Helpers.parse_simple.groups[0].entries[0]
        subject.created_at.should be_a(Time)
        subject.updated_at.should be_a(Time)
        subject.last_accessed_at.should be_a(Time)
        subject.usage_count.should eq(0)
      end
    end
  end
end
