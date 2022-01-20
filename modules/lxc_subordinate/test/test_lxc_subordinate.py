import json
import os

import pytest
from mock.mock import patch

from roles.server_base.lxc.library import lxc_subordinate


class TestSubIdMap:
    @pytest.fixture
    def subid_map_mock(self):
        mock = lxc_subordinate.SubIdMap('test_file', 1000)
        return mock

    def test_read(self, subid_map_mock, mocker):
        content = """daapd:100000:65536
git:165536:65536
gitdaemon:231072:65536
adm_server:493216:65536
"""
        with patch("builtins.open", mocker.mock_open(read_data=content)):
            subid_map_mock.read()

        assert subid_map_mock._map['daapd'] == [[100000, 65536]]
        assert list(subid_map_mock._map) == ['daapd', 'git', 'gitdaemon', 'adm_server']

    def test_free_id_new(self, subid_map_mock,):
        result = subid_map_mock.free_id()
        assert result == 1000

    def test_free_id_after_existing(self, subid_map_mock, mocker):
        content = """daapd:100000:65536
git:165536:65536
gitdaemon:231072:65536
adm_server:493216:65536
"""
        with patch("builtins.open", mocker.mock_open(read_data=content)):
            subid_map_mock.read()
        result = subid_map_mock.free_id()
        assert result == 558752

    def test_user_append_new(self, subid_map_mock):
        subid_map_mock.user_append('test', 1000, 500)
        assert subid_map_mock._map['test'] == [[1000, 500]]

    def test_user_append_overlapping(self, subid_map_mock, mocker):
        subid_map_mock._map['test'] = [[1000, 500]]
        subid_map_mock.user_append('test', 1000, 500)
        assert subid_map_mock._map['test'] == [[1000, 500]]

    def test_user_append_existing(self, subid_map_mock):
        subid_map_mock._map['test'] = [[1000, 500]]
        subid_map_mock.user_append('test', 1500, 500)
        assert subid_map_mock._map['test'] == [[1000, 500], [1500, 500]]

    def test_user_remove(self, subid_map_mock):
        subid_map_mock._map['test'] = [[1000, 500]]
        subid_map_mock.user_remove('test', 1000, 500)
        assert subid_map_mock._map['test'] == []

    def test_write(self, subid_map_mock, mocker):
        expected_result = """test1:1000:500
test1:1500:500
test2:2000:500
test2:2500:500"""
        subid_map_mock._map['test1'] = [[1000, 500], [1500, 500]]
        subid_map_mock._map['test2'] = [[2000, 500], [2500, 500]]
        with patch('builtins.open', mocker.mock_open(), create=True) as mocked_file:
            subid_map_mock.write()
            mocked_file().write.assert_called_once_with(expected_result)


class TestLxcSubordinate:
    @pytest.fixture
    def lxc_subordinate_mock(self, mocker):
        mapped_items = {
            'user': [],
            'group': []
        }
        mocker.patch.object(lxc_subordinate.LxcSubordinate, '_read_all_subids')
        mocker.patch.object(lxc_subordinate.LxcSubordinate, '_write_all_subids')
        mocker.patch.object(lxc_subordinate.LxcSubordinate, '_initialize_mapped_items')
        mock = lxc_subordinate.LxcSubordinate('test_file', 'container_owner', 'container_group', 65536, mapped_items)
        return mock

    def test_setup_mapped_items(self, lxc_subordinate_mock):
        mapped_items = {
            'user': ['games', 'daemon', 'news'],
            'group': ['tty', 'daemon', 'disk'],
        }
        lxc_subordinate_mock._setup_mapped_items(mapped_items)
        assert lxc_subordinate_mock._mapped_items == {
            'user': {
                'map_names': ['daemon', 'games', 'news'],
                'map_ids': [1, 5, 9],
                'start_subid': None,
            },
            'group': {
                'map_names': ['daemon', 'disk', 'tty'],
                'map_ids': [1, 5, 6],
                'start_subid': None,
            },
        }

    def test_get_group_id(self, lxc_subordinate_mock):
        result = lxc_subordinate_mock._get_group_id('tty')
        assert result == 5

    def test_get_user_id(self, lxc_subordinate_mock):
        result = lxc_subordinate_mock._get_user_id('news')
        assert result == 9

    def test_new_mapping_free_id(self, lxc_subordinate_mock, mocker):
        lxc_subordinate_mock._container_owner = 'root'
        lxc_subordinate_mock._range_count = 1234
        lxc_subordinate_mock._mapped_items = {
            'user': {
                'map_names': ['games', 'news'],
                'map_ids': [5, 9],
                'start_subid': None,
            },
            'group': {
                'map_names': ['disk', 'tty'],
                'map_ids': [5, 6],
                'start_subid': None,
            },
        }
        lxc_subordinate_mock._all_subids['group'] = lxc_subordinate.SubIdMap('/etc/subgid', 100000)
        lxc_subordinate_mock._all_subids['user'] = lxc_subordinate.SubIdMap('/etc/subuid', 100000)
        lxc_subordinate_mock._all_subids['user']._map['test1'] = [[100000, 500], [100600, 500]]
        lxc_subordinate_mock._all_subids['user']._map['test2'] = [[101000, 500], [101500, 500]]
        lxc_subordinate_mock.write_cache = mocker.Mock()
        lxc_subordinate_mock._all_subids['user'].write = mocker.Mock()
        lxc_subordinate_mock._all_subids['group'].write = mocker.Mock()
        lxc_subordinate_mock.new_mapping()

        assert lxc_subordinate_mock._mapped_config == {
            'user': {
                'subid': [[102000, 1234], [5, 1], [9, 1]],
                'lxc': [[0, 102000, 5], [5, 5, 1], [6, 102006, 3], [9, 9, 1], [10, 102010, 1224]]
            },
            'group': {
                'subid': [[100000, 1234], [5, 1], [6, 1]],
                'lxc': [[0, 100000, 5], [5, 5, 1], [6, 6, 1], [7, 100007, 1227]]
            }
        }
        assert len(lxc_subordinate_mock._all_subids['user']._map) == 3
        assert lxc_subordinate_mock._all_subids['user']._map['test1'] == [[100000, 500], [100600, 500]]
        assert lxc_subordinate_mock._all_subids['user']._map['test2'] == [[101000, 500], [101500, 500]]
        assert lxc_subordinate_mock._all_subids['user']._map['root'] == [[102000, 1234], [5, 1], [9, 1]]

        assert len(lxc_subordinate_mock._all_subids['group']._map) == 1
        assert lxc_subordinate_mock._all_subids['group']._map['root'] == [[100000, 1234], [5, 1], [6, 1]]

    def test_new_mapping_start_subid(self, lxc_subordinate_mock, mocker):
        lxc_subordinate_mock._container_owner = 'test1'
        lxc_subordinate_mock._range_count = 500
        lxc_subordinate_mock._mapped_items = {
            'user': {
                'map_names': ['games', 'news'],
                'map_ids': [5, 9],
                'start_subid': 100000,
            },
            'group': {
                'map_names': ['disk', 'tty'],
                'map_ids': [5, 6],
                'start_subid': None,
            },
        }
        lxc_subordinate_mock._all_subids['group'] = lxc_subordinate.SubIdMap('/etc/subgid', 100000)
        lxc_subordinate_mock._all_subids['user'] = lxc_subordinate.SubIdMap('/etc/subuid', 100000)
        lxc_subordinate_mock._all_subids['user']._map['test1'] = [[100600, 500]]
        lxc_subordinate_mock._all_subids['user']._map['test2'] = [[101000, 500], [101500, 500]]
        lxc_subordinate_mock.write_cache = mocker.Mock()
        lxc_subordinate_mock._all_subids['user'].write = mocker.Mock()
        lxc_subordinate_mock._all_subids['group'].write = mocker.Mock()
        lxc_subordinate_mock.new_mapping()

        assert lxc_subordinate_mock._mapped_config == {
            'user': {
                'subid': [[100000, 500], [5, 1], [9, 1]],
                'lxc': [[0, 100000, 5], [5, 5, 1], [6, 100006, 3], [9, 9, 1], [10, 100010, 490]]
            },
            'group': {
                'subid': [[100000, 500], [5, 1], [6, 1]],
                'lxc': [[0, 100000, 5], [5, 5, 1], [6, 6, 1], [7, 100007, 493]]
            }
        }

        assert len(lxc_subordinate_mock._all_subids['user']._map) == 2
        assert lxc_subordinate_mock._all_subids['user']._map['test1'] == [[100600, 500], [100000, 500], [5, 1], [9, 1]]
        assert lxc_subordinate_mock._all_subids['user']._map['test2'] == [[101000, 500], [101500, 500]]

        assert len(lxc_subordinate_mock._all_subids['group']._map) == 1
        assert lxc_subordinate_mock._all_subids['group']._map['test1'] == [[100000, 500], [5, 1], [6, 1]]

    def test_clean_subids_with_bigger_range(self, lxc_subordinate_mock):
        lxc_subordinate_mock._container_owner = 'test2'
        lxc_subordinate_mock._range_count = 600
        lxc_subordinate_mock._all_subids['user'] = lxc_subordinate.SubIdMap('/etc/subuid', 100000)
        lxc_subordinate_mock._all_subids['user']._map['test1'] = [[100600, 500]]
        lxc_subordinate_mock._all_subids['user']._map['test2'] = [[101000, 500], [101500, 500]]
        lxc_subordinate_mock._mapped_items = {
            'user': {
                'start_subid': None,
            },
        }

        mapping_cache = {
            'range_count': 500,
            'user': {
                'subid': [[101000, 500], [5, 1], [9, 1]],
            },
        }
        lxc_subordinate_mock._clean_subids(mapping_cache, 'user')
        assert lxc_subordinate_mock._mapped_items == {
            'user': {
                'start_subid': None,
            },
        }
        assert lxc_subordinate_mock._all_subids['user']._map['test1'] == [[100600, 500]]
        assert lxc_subordinate_mock._all_subids['user']._map['test2'] == [[101500, 500]]

    def test_clean_subids_with_matching_range(self, lxc_subordinate_mock):
        lxc_subordinate_mock._container_owner = 'test2'
        lxc_subordinate_mock._range_count = 500
        lxc_subordinate_mock._all_subids['user'] = lxc_subordinate.SubIdMap('/etc/subuid', 100000)
        lxc_subordinate_mock._all_subids['user']._map['test1'] = [[100600, 500]]
        lxc_subordinate_mock._all_subids['user']._map['test2'] = [[101000, 500], [101500, 500]]
        lxc_subordinate_mock._mapped_items = {
            'user': {
                'start_subid': None,
            },
        }

        mapping_cache = {
            'range_count': 500,
            'user': {
                'subid': [[101000, 500], [5, 1], [9, 1]],
            },
        }
        lxc_subordinate_mock._clean_subids(mapping_cache, 'user')
        assert lxc_subordinate_mock._mapped_items == {
            'user': {
                'start_subid': 101000,
            },
        }
        assert lxc_subordinate_mock._all_subids['user']._map['test1'] == [[100600, 500]]
        assert lxc_subordinate_mock._all_subids['user']._map['test2'] == [[101500, 500]]

    @pytest.mark.parametrize('container_owner,container_group,range_count', [
        ('test1', 'test2', 500),
        ('test2', 'test1', 500),
        ('test2', 'test2', 400),
    ])
    def test_validate_cache_range_diff(self, lxc_subordinate_mock, container_owner, container_group, range_count):
        lxc_subordinate_mock._container_owner = 'test2'
        lxc_subordinate_mock._container_group = 'test2'
        lxc_subordinate_mock._range_count = 500
        mapping_cache = {
            'container_owner': container_owner,
            'container_group': container_group,
            'range_count': range_count,
        }
        result = lxc_subordinate_mock._validate_cache(mapping_cache)
        assert not result

    @pytest.mark.parametrize('user,group', [
        ({'map_names': ['games'], 'map_ids': [5]}, {'map_names': ['disk', 'tty'], 'map_ids': [5, 6]}),
        ({'map_names': ['games', 'news'], 'map_ids': [5, 7]}, {'map_names': ['disk', 'tty'], 'map_ids': [5, 6]}),
        ({'map_names': ['games', 'news'], 'map_ids': [5, 9]}, {'map_names': ['disk', 'tty'], 'map_ids': [5, 7]}),
        ({'map_names': ['games', 'news'], 'map_ids': [5, 9]}, {'map_names': ['disk', 'daemon'], 'map_ids': [5, 1]}),
    ])
    def test_validate_cache_map_diff(self, lxc_subordinate_mock, user, group):
        lxc_subordinate_mock._container_owner = 'test2'
        lxc_subordinate_mock._container_group = 'test2'
        lxc_subordinate_mock._range_count = 500
        lxc_subordinate_mock._mapped_items = {
            'user': {
                'map_names': ['games', 'news'],
                'map_ids': [5, 9],
            },
            'group': {
                'map_names': ['disk', 'tty'],
                'map_ids': [5, 6],
            },
        }
        mapping_cache = {
            'container_owner': 'test2',
            'container_group': 'test2',
            'range_count': 500,
            'user': user,
            'group': group,
        }
        result = lxc_subordinate_mock._validate_cache(mapping_cache)
        assert not result

    def test_validate_cache_happy(self, lxc_subordinate_mock):
        lxc_subordinate_mock._container_owner = 'test2'
        lxc_subordinate_mock._container_group = 'test2'
        lxc_subordinate_mock._range_count = 500
        lxc_subordinate_mock._mapped_items = {
            'user': {
                'map_names': ['games', 'news'],
                'map_ids': [5, 9],
            },
            'group': {
                'map_names': ['disk', 'tty'],
                'map_ids': [5, 6],
            },
        }
        mapping_cache = {
            'container_owner': 'test2',
            'container_group': 'test2',
            'range_count': 500,
            'user': {
                'map_names': ['games', 'news'],
                'map_ids': [5, 9]
            },
            'group': {
                'map_names': ['disk', 'tty'],
                'map_ids': [5, 6]
            }
        }
        result = lxc_subordinate_mock._validate_cache(mapping_cache)
        assert result

    def test_read_cache_no_file(self, lxc_subordinate_mock, mocker):
        mocker.patch.object(os.path, 'exists', return_value=False)
        lxc_subordinate_mock._cache_filename = 'test_file'
        lxc_subordinate_mock.read_cache()

    def test_read_cache_invalid_cache(self, lxc_subordinate_mock, mocker):
        mocker.patch.object(os.path, 'exists', return_value=True)
        lxc_subordinate_mock._cache_filename = 'test_file'
        lxc_subordinate_mock._validate_cache = mocker.Mock(return_value=False)
        lxc_subordinate_mock._clean_subids = mocker.Mock(return_value=False)
        with patch("builtins.open", mocker.mock_open(read_data=json.dumps({}))):
            lxc_subordinate_mock.read_cache()
        assert not lxc_subordinate_mock.is_valid
        assert lxc_subordinate_mock._mapped_config == {
            'user': {
                'lxc': None,
                'subid': None,
            },
            'group': {
                'lxc': None,
                'subid': None,
            }
        }

    def test_read_cache_happy(self, lxc_subordinate_mock, mocker):
        lxc_subordinate_mock._all_subids['user'] = lxc_subordinate.SubIdMap('/etc/subuid', 100000)
        lxc_subordinate_mock._all_subids['user']._map['test1'] = [[1000, 300], [1, 1], [7, 1]]
        lxc_subordinate_mock._all_subids['group'] = lxc_subordinate.SubIdMap('/etc/subgid', 100000)
        lxc_subordinate_mock._all_subids['group']._map['test1'] = [[1000, 300], [1, 1], [7, 1]]
        lxc_subordinate_mock._container_owner = 'test1'
        lxc_subordinate_mock._container_group = 'test1'
        cache = {
            'user': {
                'lxc': [[0, 1000, 1], [1, 1, 1], [2, 1002, 5], [7, 7, 1], [8, 1008, 292]],
                'subid': [[1000, 300], [1, 1], [7, 1]],
            },
            'group': {
                'lxc': [[0, 1000, 1], [1, 1, 1], [2, 1002, 5], [7, 7, 1], [8, 1008, 292]],
                'subid': [[1000, 300], [1, 1], [7, 1]],
            }
        }
        mocker.patch.object(os.path, 'exists', return_value=True)
        lxc_subordinate_mock._cache_filename = 'test_file'
        lxc_subordinate_mock._validate_cache = mocker.Mock(return_value=True)
        with patch("builtins.open", mocker.mock_open(read_data=json.dumps(cache))):
            changed = lxc_subordinate_mock.read_cache()
        assert not changed
        assert lxc_subordinate_mock.is_valid
        assert lxc_subordinate_mock._mapped_config == {
            'user': {
                'lxc': [[0, 1000, 1], [1, 1, 1], [2, 1002, 5], [7, 7, 1], [8, 1008, 292]],
                'subid': [[1000, 300], [1, 1], [7, 1]],
            },
            'group': {
                'lxc': [[0, 1000, 1], [1, 1, 1], [2, 1002, 5], [7, 7, 1], [8, 1008, 292]],
                'subid': [[1000, 300], [1, 1], [7, 1]],
            }
        }
        assert lxc_subordinate_mock._all_subids['user']._map['test1'] == [[1000, 300], [1, 1], [7, 1]]
        assert lxc_subordinate_mock._all_subids['group']._map['test1'] == [[1000, 300], [1, 1], [7, 1]]

    def test_read_cache_all_subid_mismatch(self, lxc_subordinate_mock, mocker):
        lxc_subordinate_mock._all_subids['user'] = lxc_subordinate.SubIdMap('/etc/subuid', 100000)
        lxc_subordinate_mock._all_subids['user']._map['test1'] = [[1000, 300], [7, 1]]
        lxc_subordinate_mock._all_subids['group'] = lxc_subordinate.SubIdMap('/etc/subgid', 100000)
        lxc_subordinate_mock._all_subids['group']._map['test1'] = [[1000, 300]]
        lxc_subordinate_mock._container_owner = 'test1'
        lxc_subordinate_mock._container_group = 'test1'
        cache = {
            'user': {
                'lxc': [[0, 1000, 1], [1, 1, 1], [2, 1002, 5], [7, 7, 1], [8, 1008, 292]],
                'subid': [[1000, 300], [1, 1], [7, 1]],
            },
            'group': {
                'lxc': [[0, 1000, 1], [1, 1, 1], [2, 1002, 5], [7, 7, 1], [8, 1008, 292]],
                'subid': [[1000, 300], [1, 1], [7, 1]],
            }
        }
        mocker.patch.object(os.path, 'exists', return_value=True)
        lxc_subordinate_mock._cache_filename = 'test_file'
        lxc_subordinate_mock._validate_cache = mocker.Mock(return_value=True)
        with patch("builtins.open", mocker.mock_open(read_data=json.dumps(cache))):
            changed = lxc_subordinate_mock.read_cache()
        assert changed
        assert lxc_subordinate_mock.is_valid
        assert lxc_subordinate_mock._mapped_config == {
            'user': {
                'lxc': [[0, 1000, 1], [1, 1, 1], [2, 1002, 5], [7, 7, 1], [8, 1008, 292]],
                'subid': [[1000, 300], [1, 1], [7, 1]],
            },
            'group': {
                'lxc': [[0, 1000, 1], [1, 1, 1], [2, 1002, 5], [7, 7, 1], [8, 1008, 292]],
                'subid': [[1000, 300], [1, 1], [7, 1]],
            }
        }
        assert sorted(lxc_subordinate_mock._all_subids['user']._map['test1']) == sorted([[1000, 300], [1, 1], [7, 1]])
        assert sorted(lxc_subordinate_mock._all_subids['group']._map['test1']) == sorted([[1000, 300], [1, 1], [7, 1]])
