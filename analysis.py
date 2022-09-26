"""Implements a class and functions to simplify
drawing of graphs analysing token hits"""
import json
import itertools

import matplotlib.pyplot as plt
from user_agents import parse


class AnalysisGraph:
    """ Represents a graph that should be drawn. First
    define the graph via initialization, then call the draw() method with
    a list of tokenhits.
    The extraction_algorithm is a lambda function that returns whatever it is
    we want to group our hits by for graphing/analysis.
    For graphs that show something over time pass in over_time=True,
    this will automatically change graphing types and and show tokenhits
    relative to each other
    sort_function is usually the same as extraction_algorithm, but since
    internally we use a unix uniq-style function this needs to create an order
    that is equivalent (or at least compatible) with the extraction_algorithm)"""

    def __init__(self, graph_name, extraction_algorithm, over_time=False, sort_function=None):
        self.graph_name = graph_name
        self.extraction_algorithm = extraction_algorithm
        self.over_time=over_time

        if sort_function is None:
            sort_function = extraction_algorithm
        self.sort_function = sort_function


    def draw(self, list_of_all_tokenhits):
        """Draws this AnalysisGraph and pops up the finished graph. Expects
        a list of TokenHits as defined in main.py"""
        datapoint_tuples = []
        list_of_all_tokenhits.sort(key=self.sort_function)
        if self.over_time:
            # "buckets" for this are "this is the nth request",
            # so all buckets have size 1. This information is not contained
            # within a hit, it is relative,
            # so we run all our map functions over the hits (sorted
            # by our extraction algorithm) enriched with what their position
            datapoint_tuples = list(map(
                self.extraction_algorithm,
                list_of_all_tokenhits, range(len(list_of_all_tokenhits))))
        else:
            # Sort all hits into buckets
            for key, group in itertools.groupby(list_of_all_tokenhits, self.extraction_algorithm):
                group_size = sum(1 for _ in group)
                datapoint_tuples.append((key,group_size))

        self._draw_illustration_from_tuple_list(datapoint_tuples)



    def _draw_illustration_from_tuple_list(self, tuples_to_illustrate):
        """Internal function. Does the actual graphing from a list
        of tuples that contain the x/y data and are already ordered"""
        x_axis_points = []
        y_axis_points = []

        for data_tuple in tuples_to_illustrate:
            x_axis_points.append(data_tuple[0])
            y_axis_points.append(data_tuple[1])

        if self.over_time:
            _, ax = plt.subplots()
            ax.plot(x_axis_points, y_axis_points)
        else:
            plt.bar(x_axis_points, y_axis_points)

        plt.title(self.graph_name)
        plt.tight_layout()
        plt.xticks(rotation = 45)
        plt.show()

def build_graphs_over_time():
    """Returns a list of all time-relative graphs
    we want to draw.
    """
    graphs_to_draw = [
            AnalysisGraph("Requests over time",
                lambda hit, position : (hit.timestamp, position),
                over_time=True,
                sort_function=lambda hit:hit.timestamp)
            ]

    return graphs_to_draw


def build_graphs_over_all():
    """Returns a list of all graphs
    we want to draw that analyse all hits by some metric
    """
    graphs_to_draw = [
            AnalysisGraph("Requests by country",
                lambda hit: json.loads(hit.geo_info)["country"]),

            AnalysisGraph("Requests by Region",
                lambda hit: json.loads(hit.geo_info)["region"]),

            AnalysisGraph("Requests by browser family",
                lambda hit: parse(hit.useragent).browser.family),

            AnalysisGraph("Requests by os",
                lambda hit: parse(hit.useragent).os.family),

            AnalysisGraph("Requests by mobile devices",
                lambda hit: "Mobile" if parse(hit.useragent).is_mobile else "PC")
            ]
    return graphs_to_draw


def run_analyses(list_of_all_tokenhits):
    """Draws all graphs defined in build_graphs_over_time
    and build_graphs_over_all"""
    graphs_to_draw = []
    graphs_to_draw += build_graphs_over_time()
    graphs_to_draw += build_graphs_over_all()


    for graph in graphs_to_draw:
        graph.draw(list_of_all_tokenhits)
