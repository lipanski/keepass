require "spec"
require "../src/keepass"

module Helpers
  def self.parse_simple
    Keepass.parse!("./spec/fixtures/simple.kdbx", "sample")
  end

  def self.parse_groups_and_entries
    Keepass.parse!("./spec/fixtures/groups_and_entries.kdbx", "sample")
  end

  def self.parse_nested_groups
    Keepass.parse!("./spec/fixtures/nested_groups.kdbx", "sample")
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
        subject.notes.should eq("notes")
      end

      it "decodes the password properly" do
        subject = Helpers.parse_simple.groups[0].entries[0].password
        subject.should eq("pass")
      end

      it "sets the proper entry timestamps and usage count" do
        subject = Helpers.parse_simple.groups[0].entries[0]
        subject.created_at.should be_a(Time)
        subject.updated_at.should be_a(Time)
        subject.last_accessed_at.should be_a(Time)
        subject.usage_count.should eq(0)
      end
    end

    describe "with the groups_and_entries file" do
      it "parses it to a Database object" do
        subject = Helpers.parse_groups_and_entries
        subject.should be_a(Keepass::Database)
      end

      it "generates the proper child group count on the Root node" do
        subject = Helpers.parse_groups_and_entries.groups[0]
        subject.name.should eq("Root")
        subject.children.size.should eq(2)
      end

      it "sets the parent relationship correctly on the child nodes" do
        subject = Helpers.parse_groups_and_entries.groups[0]
        subject.children.each do |child|
          child.parent.should eq(subject)
        end
      end

      it "sets the proper entries to every child group" do
        first_child = Helpers.parse_groups_and_entries.groups[0].children[0]
        first_child.entries.size.should eq(2)

        second_child = Helpers.parse_groups_and_entries.groups[0].children[1]
        second_child.entries.size.should eq(2)
      end
    end
  end
end
