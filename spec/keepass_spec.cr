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

  def self.parse_utf8
    Keepass.parse!("./spec/fixtures/utf8.kdbx", "șnițel")
  end
end

describe Keepass do
  describe ".parse!" do
    describe "with the wrong password" do
      it "raises Keepass::Error::DecryptionFailed" do
        expect_raises Keepass::Error::DecryptionFailed do
          Keepass.parse!("./spec/fixtures/simple.kdbx", "wrong")
        end
      end
    end

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
        group.name.should eq("Root")
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
        subject.groups.size.should eq(2)
      end

      it "sets the parent relationship correctly on the child nodes" do
        subject = Helpers.parse_groups_and_entries.groups[0]
        subject.groups.each do |child|
          child.parent.should eq(subject)
        end
      end

      it "sets the proper entry and child count to every child group" do
        first_child = Helpers.parse_groups_and_entries.groups[0].groups[0]
        first_child.groups.size.should eq(0)
        first_child.entries.size.should eq(2)

        second_child = Helpers.parse_groups_and_entries.groups[0].groups[1]
        second_child.groups.size.should eq(0)
        second_child.entries.size.should eq(2)
      end

      it "contains the proper entries" do
        first_child_entries = Helpers.parse_groups_and_entries.groups[0].groups[0].entries
        first_child_entries[0].title.should eq("first group entry 1")
        first_child_entries[0].user_name.should eq("entry_1_user")
        first_child_entries[1].title.should eq("first group entry 2")
        first_child_entries[1].user_name.should eq("entry_2_user")

        second_child_entries = Helpers.parse_groups_and_entries.groups[0].groups[1].entries
        second_child_entries[0].title.should eq("second group entry 3")
        second_child_entries[0].user_name.should eq("entry_3_user")
        second_child_entries[1].title.should eq("second group entry 4")
        second_child_entries[1].user_name.should eq("entry_4_user")
      end
    end

    describe "with the nested_groups file" do
      it "parses it to a Database object" do
        subject = Helpers.parse_nested_groups
        subject.should be_a(Keepass::Database)
      end

      it "contains the Root level entry" do
        subject = Helpers.parse_nested_groups.groups[0].entries
        subject.size.should eq(1)
        subject.first.title.should eq("root entry")
      end

      it "contains all the nested groups" do
        subject = Helpers.parse_nested_groups
        subject.groups[0].name.should eq("Root")
        subject.groups[0].groups[0].name.should eq("first top")
        subject.groups[0].groups[0].groups[0].name.should eq("first level")
        subject.groups[0].groups[0].groups[0].groups[0].name.should eq("second level")
        subject.groups[0].groups[1].name.should eq("second top")
        subject.groups[0].groups[1].groups[0].name.should eq("second top first level")
      end

      it "contains the correct entries for the nested groups" do
        subject = Helpers.parse_nested_groups
        subject.groups[0].groups[0].groups[0].entries.size.should eq(1)
        subject.groups[0].groups[0].groups[0].entries[0].title.should eq("first level entry")
        subject.groups[0].groups[0].groups[0].groups[0].entries.size.should eq(1)
        subject.groups[0].groups[0].groups[0].groups[0].entries[0].title.should eq("second level entry")
        subject.groups[0].groups[1].groups[0].entries.size.should eq(1)
        subject.groups[0].groups[1].groups[0].entries[0].title.should eq("second top first level entry")
      end
    end

    describe "with the utf8 file" do
      it "parses it to a Database object" do
        subject = Helpers.parse_utf8
        subject.should be_a(Keepass::Database)
      end

      it "parses the group name properly" do
        subject = Helpers.parse_utf8.groups[0]
        subject.name.should eq("üüü")
      end

      it "parses the group entry properly" do
        subject = Helpers.parse_utf8.groups[0].entries[0]
        subject.title.should eq("utf8 password")
        subject.user_name.should eq("äää")
      end

      it "parses the entry password properly" do
        subject = Helpers.parse_utf8.groups[0].entries[0].password
        subject.should eq("ööö")
      end
    end
  end
end
