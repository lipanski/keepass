require "spec"
require "../../src/keepass/group"

module Helpers
  def self.build_entries(count : Int32)
    Array(Keepass::Entry).new(count) do
      random = Random.rand(9999).to_s
      uuid = "uuid " + random
      title = "title " + random
      user_name = "user " + random
      password = "pass " + random
      data = {"title" => "title", "user_name" => user_name, "password" => password}

      Keepass::Entry.new(uuid, data, Time.local, Time.local, Time.local, 0)
    end
  end
end

describe Keepass::Group do
  describe "#all_entries" do
    it "lists all the group's entries and all the subgroup entries" do
      bottom_entries = Helpers.build_entries(2)
      bottom_group = Keepass::Group.new("uuid bottom", "bottom", Array(Keepass::Group).new, bottom_entries)

      mid_1_entries = Helpers.build_entries(3)
      mid_1_group = Keepass::Group.new("uuid mid 1", "mid 1", [bottom_group], mid_1_entries)

      mid_2_entries = Helpers.build_entries(4)
      mid_2_group = Keepass::Group.new("uuid mid 2", "mid 2", Array(Keepass::Group).new, mid_2_entries)

      top_entries = Helpers.build_entries(5)
      top_group = Keepass::Group.new("uuid top", "top", [mid_1_group, mid_2_group], top_entries)

      top_group.all_entries.size.should eq(14)
      top_group.all_entries.should eq(top_entries + mid_1_entries + bottom_entries + mid_2_entries)

      mid_1_group.all_entries.size.should eq(5)
      mid_1_group.all_entries.should eq(mid_1_entries + bottom_entries)
    end
  end
end
